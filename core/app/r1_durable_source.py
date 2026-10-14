"""Runtime adapter for the durable ordinary authorization service.

The adapter owns no signing key and never reads Authority tables.  It consumes
only exact registry bytes returned over the pinned HTTPS client and produces
local observations for the existing atomic finish verifier.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json
import os
import time

from .r1_atomic_finish import TrustedLocalContext
from .control_plane import _r1_validation_semantics as sem
from .control_plane._r1_validation_stream import RegistrySlice, registry_slice
from .control_plane.r1_validation_codec import SCHEMA, c2, decode, h2, record, require


def _raw(value):
    return sem.rawhash(value)


def _put(reg, value):
    digest = h2(value) if value.get('type') in SCHEMA else _raw(value)
    reg['records'][digest] = deepcopy(value)
    return digest


def _event(reg, kind, at, value):
    reg['records'][_raw(value)] = deepcopy(value)
    _put(reg, value)
    event = record('registry_event', history_version=2,
        position={'history_version': 2, 'registry_digest': _raw(reg['header']),
                  'event_sequence': len(reg['events']) + 1},
        recorded_at=at, event_kind=kind, input_digest=_raw(value), output_digest=None)
    reg['events'].append(event)


def _merge(left, right):
    if right is None:
        return left
    if type(right) is RegistrySlice:
        right = {'header': decode(right.header_wire),
                 'events': [decode(w) for w in right.event_wires],
                 'records': {d: decode(w) for d, w in right.record_wires}}
    if left is None:
        return deepcopy(right)
    require(left['header'] == right['header'], 'registry header conflict')
    out = deepcopy(left)
    for event in right['events']:
        sequence = event['position']['event_sequence']
        if sequence <= len(out['events']):
            require(out['events'][sequence - 1] == event, 'registry event conflict')
        else:
            require(sequence == len(out['events']) + 1, 'registry event gap')
            out['events'].append(deepcopy(event))
    for digest, value in right['records'].items():
        require(digest not in out['records'] or out['records'][digest] == value,
                'registry record conflict')
        out['records'][digest] = deepcopy(value)
    return out


def _delta(reg, prior):
    if prior is None:
        return registry_slice(reg)
    if type(prior) is bytes:
        prior = registry_slice(decode(prior))
    require(c2(reg['header']) == prior.header_wire, 'registry delta header')
    known_events = prior.event_wires
    require(all(c2(reg['events'][decode(w)['position']['event_sequence'] - 1]) == w
                for w in known_events), 'registry delta predecessor')
    last = max((decode(w)['position']['event_sequence'] for w in known_events), default=0)
    known_records = dict(prior.record_wires)
    return RegistrySlice(prior.header_wire, tuple(c2(e) for e in reg['events'][last:]),
        tuple((d, c2(v)) for d, v in reg['records'].items() if d not in known_records))


class DurableAuthorizationSource:
    def __init__(self, *, client, trust, deployment, actor_identity, storage_dir):
        self.client, self.trust, self.deployment = client, trust, deployment
        self.pin, self.actor_identity = decode(trust.pin_wire), actor_identity
        self.authority = None
        self.core = {'header': sem.header(self.pin, deployment), 'events': [], 'records': {}}
        self.requests = {}
        self.storage_dir = Path(storage_dir).resolve()
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, operation_id):
        require('/' not in operation_id and '\\' not in operation_id, 'operation path identity')
        return self.storage_dir / (operation_id + '.json')

    def _remember(self, operation_id, request_wire, source_wire):
        value = {'request': request_wire.hex(),
                 'source': None if source_wire is None else source_wire.hex()}
        path = self._path(operation_id)
        if path.exists():
            old = json.loads(path.read_text(encoding='ascii'))
            require(old['request'] == value['request'] and
                    (old['source'] is None or value['source'] is None or old['source'] == value['source']),
                    'source original content conflict')
            if old['source'] is not None:
                value = old
        else:
            temporary = path.with_suffix('.tmp-' + str(os.getpid()) + '-' + str(time.time_ns()))
            raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')
            with temporary.open('xb') as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                # Link publishes once without allowing a concurrent writer to
                # replace an already published original.
                os.link(temporary, path)
            except FileExistsError:
                old = json.loads(path.read_text(encoding='ascii'))
                require(old['request'] == value['request'] and
                        (old['source'] is None or value['source'] is None or
                         old['source'] == value['source']),
                        'source original content conflict')
                if old['source'] is not None:
                    value = old
            finally:
                temporary.unlink(missing_ok=True)
        self.requests[operation_id] = (bytes.fromhex(value['request']),
            None if value['source'] is None else bytes.fromhex(value['source']))

    @staticmethod
    def now_ms():
        return time.time_ns() // 1_000_000

    def intake(self, request_wire):
        """Create the independently configured ordinary source admission."""
        request = decode(request_wire)
        intent, scope, at, d = (request['intent'], request['intent']['scope'],
                                request['intent']['created_at'], self.deployment)
        require(scope['actor_identity'] == self.actor_identity, 'source actor differs')
        return c2(record('source_admission', operation_id=intent['operation_id'],
            intent_digest=h2(intent), source_decision_digest=h2(request['source_decision']),
            identity_digest=h2(intent['identity']), scope_digest=h2(scope),
            **{k: scope[k] for k in ('actor_identity', 'caller_runtime_id', 'session_id',
                                     'lease_id', 'lease_generation')},
            admitted_at=at, session_issued_at=at - 1, session_expires_at=at + 60_000,
            lease_issued_at=at - 1, lease_expires_at=at + 60_000,
            normal_business_admission=True, core_installation_id=d.core_installation_id,
            deployment_admission_digest=sem.sha(d.deployment_bytes),
            component_artifact_digest=sem.sha(d.component_bytes),
            trust_config_digest=h2(self.pin)))

    def admit_original(self, request_wire, source_wire):
        expected = self.intake(request_wire)
        require(source_wire == expected, 'source admission original differs')
        operation_id = decode(request_wire)['intent']['operation_id']
        old = self.requests.get(operation_id)
        require(old is None or old == (request_wire, source_wire),
                'source original content conflict')
        self._remember(operation_id, request_wire, source_wire)
        return source_wire

    def refresh(self, reply, request_wire, *, core_history=None, authority_history=None):
        self.authority = _merge(self.authority, authority_history)
        self.authority = _merge(self.authority, reply.authority)
        self.core = _merge(self.core, core_history)
        operation_id = decode(request_wire)['intent']['operation_id']
        if operation_id not in self.requests:
            self._remember(operation_id, request_wire, None)

    def ensure_execution(self, request_wire, source_wire):
        self.admit_original(request_wire, source_wire)
        after = 0 if self.authority is None else len(self.authority['events'])
        reply = self.client.ensure_execution(request_wire, source_wire, authority_after=after)
        self.refresh(reply, request_wire)

    def ensure_permit(self, request_wire, authority_history, core_history):
        self.authority = _merge(self.authority, authority_history)
        self.core = _merge(self.core, core_history)
        operation_id = decode(request_wire)['intent']['operation_id']
        after = 0 if self.authority is None else len(self.authority['events'])
        reply = self.client.ensure_permit(operation_id, request_wire, authority_after=after)
        self.refresh(reply, request_wire)

    def _binding(self, operation_id):
        require(self.authority is not None, 'Authority registry unavailable')
        grants = [v for v in self.authority['records'].values()
                  if v.get('type') == 'execution_grant' and v['operation_id'] == operation_id]
        require(grants, 'operation grant unavailable')
        grant = max(grants, key=lambda v: v['grant_sequence'])
        return {k: grant[k] for k in ('runtime_principal', 'session_id',
                                      'policy_digest', 'inventory_digest')}

    def _observe(self, request):
        operation_id = request['intent']['operation_id']
        binding, at = self._binding(operation_id), self.now_ms()
        kinds = {'POLICY_REGISTER': 'POLICY_OBSERVED',
                 'SESSION_CREATE': 'SESSION_OBSERVED',
                 'INVENTORY_ACCEPT': 'INVENTORY_OBSERVED',
                 'PERMIT_ISSUED': 'PERMIT_OBSERVED'}
        observed = {self.core['records'][e['input_digest']].get('object_digest')
                    for e in self.core['events'] if e['event_kind'] in kinds.values()}
        wanted = {binding['policy_digest'], binding['inventory_digest']}
        revocable = {binding['policy_digest']}
        for value in self.authority['records'].values():
            if value.get('session_id') == binding['session_id'] and 'enrollment' in value:
                wanted.add(_raw(value))
                revocable.add(_raw(value))
            if value.get('type') == 'local_finish_permit' and value['operation_id'] == operation_id:
                wanted.add(h2(value))
                revocable.add(h2(value))
        for event in self.authority['events']:
            kind = kinds.get(event['event_kind'])
            if kind is None:
                continue
            for digest in (event['output_digest'], event['input_digest']):
                value = self.authority['records'].get(digest, {})
                object_digest = (h2(value) if value.get('type') in SCHEMA else _raw(value))
                if object_digest in wanted and object_digest not in observed:
                    observation = record('local_observation', history_version=2,
                        authority_position=event['position'], authority_event_digest=_raw(event),
                        object_digest=object_digest)
                    _event(self.core, kind, at, observation)
                    observed.add(object_digest)
        # A local APPLY rechecks current observed policy/session/permit state.
        # Carry forward only revocations for objects already relevant to this
        # operation; grant/lease revocation remains an Authority action concern.
        for event in self.authority['events']:
            if event['event_kind'] not in ('POLICY_REVOKE', 'SESSION_REVOKE', 'PERMIT_REVOKE'):
                continue
            revocation = self.authority['records'][event['input_digest']]
            digest = _raw(revocation)
            if revocation['object_digest'] in revocable and digest not in observed:
                observation = record('local_observation', history_version=2,
                    authority_position=event['position'], authority_event_digest=_raw(event),
                    object_digest=digest)
                _event(self.core, 'REVOCATION_OBSERVED', at, observation)
                observed.add(digest)
        protected = any(e['event_kind'] == 'LOCAL_PROTECTION' and
            self.core['records'][e['input_digest']]['policy_digest'] == binding['policy_digest']
            for e in self.core['events'])
        if not protected:
            _event(self.core, 'LOCAL_PROTECTION', at,
                record('local_protection', history_version=2,
                       policy_digest=binding['policy_digest'], component_valid=True,
                       policy_active=True, context_kind='INTACT_ADMITTED'))

    def capture(self, operation_id, action, *, local_history=None, authority_history=None):
        self.authority = _merge(self.authority, authority_history)
        self.core = _merge(self.core, local_history)
        request_wire = self.requests.get(operation_id, (None, None))[0]
        if request_wire is None:
            path = self._path(operation_id)
            require(path.is_file(), 'source original request unavailable')
            saved = json.loads(path.read_text(encoding='ascii'))
            request_wire = bytes.fromhex(saved['request'])
            self.requests[operation_id] = (request_wire,
                None if saved['source'] is None else bytes.fromhex(saved['source']))
        require(request_wire is not None, 'source original request unavailable')
        self._observe(decode(request_wire))
        return TrustedLocalContext(_delta(self.authority, authority_history),
            _delta(self.core, local_history), checked_at=self.now_ms(),
            **self._binding(operation_id))
