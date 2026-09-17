"""Ordinary Scoped V2 coordination using durable original evidence and real clients.

The source is an explicitly installed authenticated admission/registry/time
adapter. Its issuance callbacks may communicate only outside local transactions.
No default adapter, restore route, override producer, or lifecycle permission is
installed by this module.
"""
from copy import deepcopy
from uuid import uuid4

from ._r1_coordination_journal import CoordinationJournal
from .r1_atomic_finish import (FinishInput, ScopedCoreFinisher, TrustedLocalContext,
                               _pack, _unpack)
from .control_plane import _r1_validation_semantics as sem
from .control_plane._r1_validation_stream import BoundedHistory, RegistrySlice, WindowEvidence, registry_slice
from .control_plane.r1_scoped_messages import AuthorityReply
from .control_plane.r1_validation import ChainBoundary
from .control_plane.r1_validation_codec import ContractError, c2, decode, h2, obj, record, require


def build_mutation_request(*, identity, scope, payload, mutation_id, decision,
                           created_at, reason='Ordinary governed mutation',
                           operation_id=None, local_commit_id=None,
                           source_authorization_id=None):
    """Derive both exact candidates before the first durable/network boundary."""
    require(decision in ('COMMIT', 'ABORT'), 'ordinary decision required')
    intent = obj('business_intent', operation_id=operation_id or str(uuid4()),
        mutation_id=mutation_id, local_commit_id=local_commit_id or str(uuid4()),
        identity=deepcopy(identity), scope=deepcopy(scope), payload=deepcopy(payload),
        requested_decision=decision, created_at=created_at, reason=reason)
    source = obj('source_decision', authorization_id=source_authorization_id or str(uuid4()),
        authorization_kind='CALLER_INTENT', intent_digest=h2(intent), identity_digest=h2(identity),
        scope_digest=h2(scope), authorization_principal=scope['actor_identity'],
        requested_decision=decision, created_at=created_at)
    return c2(obj('mutation_request', intent=intent, source_decision=source,
                  commit=sem.branch(intent, source, 'COMMIT'), abort=sem.branch(intent, source, 'ABORT')))


class ScopedCoreCoordinator:
    def __init__(self, *, journal, finisher, client, source, checkpoint_hook=None):
        require(type(journal) is CoordinationJournal and type(finisher) is ScopedCoreFinisher,
                'explicit durable coordination and atomic finish stores required')
        require(source is not None and all(callable(getattr(source, n, None)) for n in
            ('admit_original', 'ensure_execution', 'ensure_permit', 'refresh', 'capture', 'now_ms')),
            'authenticated original/source/issuance adapters required')
        require(finisher.source is source, 'coordination and finish must share the protected source')
        self.journal, self.finisher, self.client, self.source = journal, finisher, client, source
        self.trust, self.deployments = finisher.trust, finisher.deployments
        self.runtime_principal, self.material, self.pin = finisher.runtime_principal, finisher.material, finisher.pin
        self.checkpoint_hook = checkpoint_hook
        self._verified_cache = None
        with finisher.store.transaction(write=False) as db:
            metadata = db.execute('SELECT * FROM metadata WHERE id=1').fetchone()
            require(journal.scope_wire == metadata['scope_wire'] and
                    journal.checkpoint_wire == metadata['initial_checkpoint_wire'], 'journal/finish independent seeds differ')
        scope = decode(journal.scope_wire)
        self.boundary = ChainBoundary(c2(scope['identity']), journal.checkpoint_wire, journal.checkpoint_wire,
            scope['owner_identity'], scope['owner_version'], scope['continuity_epoch'],
            scope['storage_generation_id'], scope['control_plane_generation_id'], scope['trust_domain_id'])

    def _hook(self, stage):
        if self.checkpoint_hook is not None:
            self.checkpoint_hook(stage)

    @staticmethod
    def _slice(value):
        return value if type(value) is RegistrySlice else registry_slice(decode(value))

    def _engine(self, db):
        rows = db.execute('SELECT sequence,evidence_wire FROM windows ORDER BY sequence').fetchall()
        require([r[0] for r in rows] == list(range(1, len(rows) + 1)), 'missing original coordination window')
        # Import actual Slice 02 committed evidence, including APPLY. This is a
        # read of the paired local store, never a source-supplied completion.
        with self.finisher.store.transaction(write=False) as finish_db:
            finished = finish_db.execute('SELECT sequence,evidence_wire FROM history_windows ORDER BY sequence').fetchall()
            require([r[0] for r in finished] == list(range(1, len(finished) + 1)), 'missing original finish window')
        journal_wires = tuple(r['evidence_wire'] for r in rows)
        finish_wires = tuple(r['evidence_wire'] for r in finished)
        cache = self._verified_cache
        if cache is not None and journal_wires[:len(cache[0])] == cache[0] and finish_wires[:len(cache[1])] == cache[1]:
            engine = cache[2].fork()
            journal_start, finish_start = len(cache[0]), len(cache[1])
        else:
            engine = BoundedHistory(self.trust, self.deployments, self.boundary)
            journal_start = finish_start = 0
        def append(target, wire):
            original = _unpack(wire)
            require(not original.restore_evidence, 'ordinary coordinator cannot import restoration')
            target.append(self.finisher._window(original.evidence), operation='REGISTRY_RELATIONS')
        finish_index = finish_start
        for wire in journal_wires[journal_start:]:
            while True:
                trial = engine.fork()
                try:
                    append(trial, wire)
                except ContractError:
                    # The paired journals have independent insertion orders.
                    # A later coordination delta may depend on an actual APPLY
                    # which committed in the other file. Add its original
                    # evidence before retrying; never reuse the failed trial.
                    if finish_index >= len(finish_wires):
                        raise
                    append(engine, finish_wires[finish_index])
                    finish_index += 1
                else:
                    engine = trial
                    break
        for wire in finish_wires[finish_index:]:
            append(engine, wire)
        # A cache never replaces original bytes. Every read compares the entire
        # cached provenance prefixes, and restart rebuilds using those records.
        engine._coordination_finish_wires = finish_wires
        self._verified_cache = (journal_wires, finish_wires, engine.fork())
        return engine

    def _window(self, row, authority, core):
        return WindowEvidence((row['request_wire'],), authority,
            ((self.runtime_principal, core),) if core is not None else (),
            source_admission_wires=(row['source_wire'],))

    @staticmethod
    def _with_original_dependencies(db, engine, window):
        """Supply originals for newly observed peers from this local journal.

        A complete Authority delta can contain qualification for another
        concurrent pending operation. Its actual event references select the
        dependency; remote data never supplies or manufactures its original
        request/admission. The unchanged kernel still verifies the whole delta
        and its 64-operation bound.
        """
        authority_records = dict(engine.registry()['records'])
        authority_records.update((digest, decode(raw)) for digest, raw in window.authority.record_wires)
        touched = set()
        for principal, part in ((None, window.authority), *window.cores):
            known = engine.registry() if principal is None else engine.registry(principal) if principal in engine.core_states else {'events': [], 'records': {}}
            records = dict(known['records'])
            records.update((digest, decode(raw)) for digest, raw in part.record_wires)
            for raw in part.event_wires:
                event = decode(raw)
                if event['position']['event_sequence'] <= len(known['events']):
                    continue
                for digest in (event['input_digest'], event['output_digest']):
                    if digest is None:
                        continue
                    value = records.get(digest)
                    require(type(value) is dict, 'event original input/output missing')
                    if 'operation_id' in value:
                        touched.add(value['operation_id'])
                    observed = authority_records.get(value.get('object_digest'))
                    if observed is not None and 'operation_id' in observed:
                        touched.add(observed['operation_id'])
        present = {decode(raw)['intent']['operation_id'] for raw in window.request_wires}
        requests, admissions = list(window.request_wires), list(window.source_admission_wires)
        for operation_id in sorted(touched - set(engine.requests) - present):
            original = db.execute('SELECT request_wire,source_wire FROM attempts WHERE operation_id=?', (operation_id,)).fetchone()
            require(original is not None, 'observed peer lacks locally persisted admitted original request')
            require(decode(original['request_wire'])['intent']['operation_id'] == operation_id,
                    'persisted peer original operation differs')
            requests.append(original['request_wire'])
            admissions.append(original['source_wire'])
        return WindowEvidence(tuple(requests), window.authority, window.cores,
                              tuple(admissions), window.context_wires)

    @staticmethod
    def _delta(part, known):
        """Remove exact verified overlap BEFORE entering the bounded verifier.

        This accepts a protected source's cumulative in-process snapshot, but
        preserves every actually new event/record. Oversized new deltas still
        reach and fail the original window bound; nothing is truncated.
        """
        require(type(part) is RegistrySlice and decode(part.header_wire) == known['header'],
                'original registry header differs')
        events, records, previous = [], [], 0
        for raw in part.event_wires:
            event = decode(raw); sequence = event['position']['event_sequence']
            require(sequence > previous, 'source event order/duplicate position')
            previous = sequence
            if sequence <= len(known['events']):
                require(c2(known['events'][sequence - 1]) == raw, 'original event overlap conflict')
            else:
                events.append(raw)
        for digest, raw in part.record_wires:
            if digest in known['records']:
                require(c2(known['records'][digest]) == raw, 'original record overlap conflict')
            else:
                records.append((digest, raw))
        return RegistrySlice(part.header_wire, tuple(events), tuple(records))

    def _known_core(self, engine):
        return engine.registry(self.runtime_principal) if self.runtime_principal in engine.core_states else {
            'header': sem.header(self.pin, self.material), 'events': [], 'records': {}}

    def _between(self, row, desired, base):
        """Original evidence needed to advance a particular verified ledger."""
        operations = [row['operation_id'], *sorted(set(desired.requests) - set(base.requests) - {row['operation_id']})]
        return WindowEvidence(tuple(desired.request_wires[op] for op in operations),
            self._delta(registry_slice(desired.registry()), base.registry()),
            ((self.runtime_principal, self._delta(registry_slice(desired.registry(self.runtime_principal)),
                                                  self._known_core(base))),),
            source_admission_wires=tuple(c2(desired.admissions[op]) for op in operations))

    def _save(self, db, row, engine):
        # Derive from the resulting verified state, not merely the source's
        # latest delta. A reply may have already advanced this engine before a
        # capture returns an empty Authority delta; those facts must be saved.
        base = self._engine(db)
        window = self._between(row, engine, base)
        known = {r[0] for r in db.execute('SELECT evidence_wire FROM windows')}
        for wire in base._coordination_finish_wires:
            if wire not in known:
                # Copy only bytes actually read and verified from the paired
                # atomic journal. This records the dependency before later
                # deltas without manufacturing another local APPLY fact.
                sequence = db.execute('SELECT count(*) FROM windows').fetchone()[0] + 1
                db.execute('INSERT INTO windows VALUES(?,?)', (sequence, wire))
                known.add(wire)
        sequence = db.execute('SELECT count(*) FROM windows').fetchone()[0] + 1
        # FinishInput is only the existing safe internal serialization envelope;
        # no permit is asserted by this pre-terminal journal.
        item = FinishInput(row['operation_id'], window, '0' * 64, self.boundary)
        db.execute('INSERT INTO windows VALUES(?,?)', (sequence, _pack(item)))

    def _context(self, db, engine, row, action):
        local = registry_slice(engine.registry(self.runtime_principal)) if self.runtime_principal in engine.core_states else None
        context = self.source.capture(row['operation_id'], action,
            local_history=local, authority_history=registry_slice(engine.registry()))
        require(type(context) is TrustedLocalContext and context.runtime_principal == self.runtime_principal,
                'authenticated local context required')
        window = self._window(row,
            self._delta(self._slice(context.authority_history), engine.registry()),
            self._delta(self._slice(context.core_history), self._known_core(engine)))
        window = self._with_original_dependencies(db, engine, window)
        engine.append(window, operation='REGISTRY_RELATIONS')
        return context, window

    def _qualify(self, engine, row, context, actions):
        now = self.source.now_ms()
        core, state = engine.registry(self.runtime_principal), engine.core_states[self.runtime_principal]
        require(type(now) is int and now >= context.checked_at and
                (not core['events'] or now >= core['events'][-1]['recorded_at']), 'trusted local clock regressed')
        subject = sem.subject_from(state, context.policy_digest, context.inventory_digest, context.session_id)
        require(subject['policy']['runtime_principal'] == self.runtime_principal and
                subject['enrollment']['context_kind'] == 'INTACT_ADMITTED', 'ordinary authenticated component required')
        sem.local_subject(state, subject, self.pin, self.material, now, actions, None)
        sem.verify_finish_inventory(subject['policy'], subject['inventory'], {'request': decode(row['request_wire'])})
        return now

    def persist_intent(self, request_wire, source_admission_wire):
        require(type(request_wire) is bytes and type(source_admission_wire) is bytes, 'exact original wires required')
        request = decode(request_wire)
        sem.verify_request(request, self.pin, request['intent']['scope']['actor_identity'])
        operation_id = request['intent']['operation_id']
        with self.journal.transaction(write=False) as db:
            old = db.execute('SELECT * FROM attempts WHERE operation_id=?', (operation_id,)).fetchone()
            if old is not None:
                require(old['request_wire'] == request_wire and old['source_wire'] == source_admission_wire,
                        'same ID different original content')
                # History survives expiry of its original intake credentials.
                # The driver separately checks the current query/action caller.
                return operation_id
        admitted = self.source.admit_original(request_wire, source_admission_wire)
        require(type(admitted) is bytes and admitted == source_admission_wire, 'original admission source differs')
        sem.verify_source_admission(decode(admitted), request, self.pin, self.material)
        intent, scope = request['intent'], decode(self.journal.scope_wire)
        require(intent['identity'] == scope['identity'], 'original identity differs from actual local installation')
        for name, key in (('actor_identity', 'owner_identity'), ('owner_version', 'owner_version'),
                          ('continuity_epoch', 'continuity_epoch'), ('storage_generation_id', 'storage_generation_id'),
                          ('control_plane_generation_id', 'control_plane_generation_id'), ('trust_domain_id', 'trust_domain_id')):
            require(intent['scope'][name] == scope[key], 'original request local scope differs')
        with self.journal.transaction() as db:
            old = db.execute('SELECT * FROM attempts WHERE operation_id=?', (operation_id,)).fetchone()
            if old is not None:
                require(old['request_wire'] == request_wire and old['source_wire'] == admitted, 'same ID different original content')
                return operation_id
            require(db.execute('SELECT 1 FROM attempts WHERE mutation_id=? OR local_commit_id=?',
                (intent['mutation_id'], intent['local_commit_id'])).fetchone() is None, 'mutation/local commit identity conflict')
            with self.finisher.store.transaction(write=False) as finish_db:
                actual = finish_db.execute('SELECT checkpoint_wire FROM metadata WHERE id=1').fetchone()[0]
                require(actual == c2(sem.before_checkpoint(request)), 'new intent has stale actual local predecessor')
            db.execute('INSERT INTO attempts(operation_id,mutation_id,local_commit_id,request_wire,source_wire) VALUES(?,?,?,?,?)',
                (operation_id, intent['mutation_id'], intent['local_commit_id'], request_wire, admitted))
        self._hook('intent_saved')
        return operation_id

    def _local_history(self):
        with self.journal.transaction(write=False) as db:
            engine = self._engine(db)
            return registry_slice(engine.registry(self.runtime_principal)) if self.runtime_principal in engine.core_states else None

    def _authority_history(self):
        with self.journal.transaction(write=False) as db:
            return registry_slice(self._engine(db).registry())

    def _dispatch_history(self):
        """Send original Core delta after the last peer-proven publication.

        An earlier Authority terminal proves it consumed that publication. Its
        exact Core prefix already belongs to the peer's durable evidence; the
        delta includes subsequent real APPLY and current coordination events.
        """
        with self.journal.transaction(write=False) as db:
            engine = self._engine(db)
            core, authority = engine.registry(self.runtime_principal), engine.registry()
            start = 0
            for receipt in engine.authority_state['terminals'].values():
                snapshot = sem.record_by(authority, receipt['terminal_execution_digest'], 'execution_snapshot')
                payload = sem.record_by(authority, snapshot['action_input_digest'], 'action_input')
                publication = sem.record_by(authority, payload['publication_digest'], 'dispatch_publication')
                if publication['position']['registry_digest'] == sem.rawhash(core['header']):
                    start = max(start, publication['position']['event_sequence'])
            events = core['events'][start:]
            wanted = set()
            def visit(value):
                if type(value) is dict:
                    for child in value.values():
                        visit(child)
                elif type(value) is list:
                    for child in value:
                        visit(child)
                elif type(value) is str and value in core['records'] and value not in wanted:
                    wanted.add(value)
                    visit(core['records'][value])
            for event in events:
                visit(event)
            return RegistrySlice(c2(core['header']), tuple(c2(e) for e in events),
                tuple((digest, c2(core['records'][digest])) for digest in sorted(wanted)))

    def _query_remote(self, operation_id, request_wire):
        return self.client.query(operation_id, request_wire,
            authority_after=len(self._authority_history().event_wires))

    def _receive(self, operation_id, reply):
        require(type(reply) is AuthorityReply and reply.state in ('ABSENT', 'PREPARED', 'FIX_ACCEPTED', 'TERMINAL'),
                'explicit authenticated operation reply required')
        row = self.journal.load(operation_id)
        require(reply.request_wire is None if reply.state == 'ABSENT' else reply.request_wire == row['request_wire'],
                'Authority reply original request conflict')
        # The source consumes only the authenticated pinned transport response;
        # subsequent product replay independently checks all its original facts.
        self.source.refresh(reply, row['request_wire'], core_history=self._local_history(),
                            authority_history=self._authority_history())
        denied = None
        with self.journal.transaction() as db:
            row = dict(db.execute('SELECT * FROM attempts WHERE operation_id=?', (operation_id,)).fetchone())
            engine = self._engine(db)
            incoming = self._with_original_dependencies(db, engine, self._window(row, reply.authority, None))
            engine.append(incoming, operation='REGISTRY_RELATIONS')
            context, window = self._context(db, engine, row, 'QUERY_EXISTING')
            facts = engine.authority_state
            found = facts['terminals'].get(operation_id)
            fix = facts['fixes'].get((operation_id, 'NORMAL'))
            ack = facts['acks'].get(operation_id)
            state = 'TERMINAL' if found is not None else 'FIX_ACCEPTED' if fix is not None else 'PREPARED' if ack is not None else 'ABSENT'
            order = {'ABSENT': 0, 'PREPARED': 1, 'FIX_ACCEPTED': 2, 'TERMINAL': 3}
            require(order[reply.state] <= order[state], 'reply phase lacks original registry evidence')
            for name, value in (('ack_wire', ack), ('acceptance_wire', fix), ('terminal_wire', found)):
                expected = None if value is None else c2(value)
                present_from = {'ack_wire': 1, 'acceptance_wire': 2, 'terminal_wire': 3}[name]
                # An older in-flight same-ID response may arrive after another
                # process durably observed advancement. Check its exact original
                # facts without regressing that later durable observation.
                claimed = expected if order[reply.state] >= present_from else None
                require(getattr(reply, name) == claimed, 'reply evidence differs from original registry')
            # An action denial must not erase an already verified revocation or
            # other observed historical fact. This journal entry alone grants
            # neither a consumable dispatch nor APPLY permission.
            self._save(db, row, engine)
            try:
                self._qualify(engine, row, context, {'QUERY_EXISTING', 'PERSIST_COORDINATION'})
            except Exception as exc:
                denied = exc
            if denied is None:
                for name, value in (('ack_wire', ack), ('acceptance_wire', fix), ('terminal_wire', found)):
                    if value is not None:
                        self.journal.freeze(db, operation_id, **{name: c2(value)})
        if denied is not None:
            raise denied
        self._hook('ack_saved' if reply.state == 'PREPARED' else
                   'fix_accepted_saved' if reply.state == 'FIX_ACCEPTED' else
                   'terminal_saved' if reply.state == 'TERMINAL' else 'absence_observed')
        return state

    def _local_action(self, operation_id, publication=False):
        denied = None
        with self.journal.transaction() as db:
            row = dict(db.execute('SELECT * FROM attempts WHERE operation_id=?', (operation_id,)).fetchone())
            field = 'publication_wire' if publication else 'proposal_wire'
            if row[field] is not None:
                return
            engine = self._engine(db)
            context, observed = self._context(db, engine, row, 'PUBLISH_DISPATCH' if publication else 'PROPOSE_DISPATCH')
            self._save(db, row, engine)
            actions = {'QUERY_EXISTING', 'PERSIST_COORDINATION'} if publication else {'PERSIST_COORDINATION', 'FIX_ORIGINAL_DISPATCH'}
            try:
                now = self._qualify(engine, row, context, actions)
            except Exception as exc:
                denied = exc
            if denied is None:
                self._create_local_action(db, row, engine, context, now, publication)
        if denied is not None:
            raise denied
        self._hook('dispatch_saved' if publication else 'proposal_saved')

    def _create_local_action(self, db, row, engine, context, now, publication):
        operation_id = row['operation_id']
        field = 'publication_wire' if publication else 'proposal_wire'
        request = decode(row['request_wire']); intent = request['intent']; ack = decode(row['ack_wire'])
        core = deepcopy(engine.registry(self.runtime_principal))
        common = {'operation_id': operation_id, 'request_digest': h2(request), 'source_decision_digest': h2(request['source_decision'])}
        before = sem.before_checkpoint(request)
        if not publication:
            stage = obj('staged_evidence', operation_id=operation_id, local_commit_id=intent['local_commit_id'],
                request_digest=h2(request), ack_digest=h2(ack), commit_candidate_digest=h2(request['commit']), abort_candidate_digest=h2(request['abort']))
            decision = intent['requested_decision']
            auth = obj('terminal_authorization', authorization_id=str(uuid4()), **common,
                local_commit_id=intent['local_commit_id'], ack_digest=h2(ack), decision=decision,
                candidate_digest=h2(request[decision.lower()]), staging_evidence_digest=h2(stage),
                no_local_business_commit=decision == 'ABORT', created_at=now)
            output = record('dispatch_record', history_version=2, proposal_position=sem.position(core),
                kind='NORMAL', **common, local_commit_id=intent['local_commit_id'], ack_digest=h2(ack),
                staging_evidence_digest=h2(stage), semantic_authorization_digest=h2(auth),
                runtime_principal=self.runtime_principal, session_id=context.session_id,
                core_installation_id=self.material.core_installation_id, created_at=now,
                no_local_business_commit=decision == 'ABORT', before_checkpoint=before)
            proposal = None
        else:
            auth, proposal, acceptance = decode(row['authorization_wire']), decode(row['proposal_wire']), decode(row['acceptance_wire'])
            output = record('dispatch_publication', history_version=2, position=sem.position(core),
                published_at=now, proposal_digest=sem.rawhash(proposal), fix_acceptance_digest=sem.rawhash(acceptance))
            core['records'][sem.rawhash(acceptance)] = acceptance
        payload = record('action_input', history_version=2, **common, ack_digest=h2(ack), authorization_digest=h2(auth),
            proposal_digest=None if proposal is None else sem.rawhash(proposal), publication_digest=None)
        snapshot = record('local_snapshot', history_version=2, position=sem.position(core), checked_at=now,
            action='PUBLISH_DISPATCH' if publication else 'PROPOSE_DISPATCH', runtime_principal=self.runtime_principal,
            session_id=context.session_id, policy_digest=context.policy_digest, inventory_digest=context.inventory_digest,
            **common, target_digest=sem.rawhash(before), action_input_digest=sem.rawhash(payload))
        event = record('registry_event', history_version=2, position=sem.position(core), recorded_at=now,
            event_kind='PUBLICATION' if publication else 'PROPOSAL', input_digest=sem.rawhash(snapshot), output_digest=sem.rawhash(output))
        for value in (auth, before, payload, snapshot, output):
            core['records'][h2(value) if value.get('type') in sem.SCHEMA else sem.rawhash(value)] = value
        core['events'].append(event)
        window = self._window(row,
            RegistrySlice(c2(engine.registry()['header']), (), ()),
            self._delta(registry_slice(core), self._known_core(engine)))
        engine.append(window, operation='REGISTRY_RELATIONS')
        self._save(db, row, engine)
        frozen = {field: c2(output)}
        if not publication:
            frozen['authorization_wire'] = c2(auth)
        self.journal.freeze(db, operation_id, **frozen)

    def _finish(self, operation_id):
        row = self.journal.load(operation_id)
        with self.finisher.store.transaction(write=False) as db:
            saved = db.execute('SELECT status FROM operations WHERE operation_id=?', (operation_id,)).fetchone()
            finalized = saved is not None and saved[0] == 'FINALIZED'
        if finalized:
            result = self.finisher.query(operation_id, row['request_wire'])
            with self.journal.transaction() as db:
                db.execute('UPDATE attempts SET completed=1 WHERE operation_id=?', (operation_id,))
            self._hook('completed_saved')
            return result
        with self.journal.transaction(write=False) as db:
            engine = self._engine(db)
            authority = registry_slice(engine.registry())
            core = registry_slice(engine.registry(self.runtime_principal))
        warm = FinishInput(operation_id, self._window(row,
            RegistrySlice(authority.header_wire, (), ()), None), '0' * 64)
        with self.finisher.store.transaction(write=False) as finish_db:
            # Rebuild only existing raw history before requesting a short-lived
            # permit. The real finish still rechecks all raw cache provenance
            # and current eligibility; this performs neither issue nor APPLY.
            self.finisher._engine(finish_db, warm)
        self.source.ensure_permit(row['request_wire'], authority, core)
        self._receive(operation_id, self._query_remote(operation_id, row['request_wire']))
        with self.journal.transaction() as db:
            engine = self._engine(db)
            context, window = self._context(db, engine, row, 'PERSIST_COORDINATION')
            self._save(db, row, engine)
            permit_digest = engine.authority_state['permit_pointer'].get(operation_id)
            require(permit_digest is not None, 'current issued finish permit missing')
            # Existing finisher verifies both this evidence and the current
            # local source, then atomically saves all exact effects/proofs.
            provisional = FinishInput(operation_id, window, permit_digest)
            with self.finisher.store.transaction(write=False) as finish_db:
                finish_base = self.finisher._engine(finish_db, provisional)
            item = FinishInput(operation_id, self._between(row, engine, finish_base), permit_digest)
        self._hook('before_local_finish')
        self.finisher.persist(item)
        result = self.finisher.finish(item)
        self._hook('local_finish_returned')
        with self.journal.transaction() as db:
            db.execute('UPDATE attempts SET completed=1 WHERE operation_id=?', (operation_id,))
        self._hook('completed_saved')
        return result

    def _drive(self, operation_id):
        row = self.journal.load(operation_id)
        if row['completed']:
            return self.finisher.query(operation_id, row['request_wire'])
        with self.journal.transaction(write=False) as db:
            self._engine(db)
        # Controlled issuance/admission adapters may register the original
        # operation's lawful recovery subject only after its intent is durable.
        # They cannot create Ack/FIX/terminal, and an existing historical grant
        # is not itself treated as current eligibility by this coordinator.
        self.source.ensure_execution(row['request_wire'], row['source_wire'])
        # Even after a lost PREPARE response recovery starts with a scoped query.
        # UNKNOWN/transport errors propagate; only a verified ABSENT permits POST.
        state = self._receive(operation_id, self._query_remote(operation_id, row['request_wire']))
        if state == 'ABSENT':
            self.source.ensure_execution(row['request_wire'], row['source_wire'])
            self._hook('before_prepare_send')
            state = self._receive(operation_id, self.client.prepare(row['request_wire'], row['source_wire'],
                authority_after=len(self._authority_history().event_wires)))
        if state == 'PREPARED':
            self._local_action(operation_id)
            row = self.journal.load(operation_id)
            self.source.ensure_execution(row['request_wire'], row['source_wire'])
            self._hook('before_fix_send')
            state = self._receive(operation_id, self.client.decide(operation_id, row['request_wire'],
                row['authorization_wire'], row['proposal_wire'], None, self._dispatch_history(),
                authority_after=len(self._authority_history().event_wires)))
        if state == 'FIX_ACCEPTED':
            self._local_action(operation_id, publication=True)
            row = self.journal.load(operation_id)
            self.source.ensure_execution(row['request_wire'], row['source_wire'])
            self._hook('before_terminal_send')
            state = self._receive(operation_id, self.client.decide(operation_id, row['request_wire'],
                row['authorization_wire'], row['proposal_wire'], row['publication_wire'], self._dispatch_history(),
                authority_after=len(self._authority_history().event_wires)))
        require(state == 'TERMINAL', 'original operation still unresolved')
        return self._finish(operation_id)

    def governed_mutation(self, request_wire, source_admission_wire):
        return self._drive(self.persist_intent(request_wire, source_admission_wire))

    def abort_mutation(self, request_wire, source_admission_wire):
        require(decode(request_wire)['intent']['requested_decision'] == 'ABORT', 'explicit original ABORT required')
        return self.governed_mutation(request_wire, source_admission_wire)

    def recover(self, operation_id):
        return self._drive(operation_id)

    def query(self, operation_id, request_wire):
        row = self.journal.load(operation_id)
        require(row['request_wire'] == request_wire, 'query original content conflict')
        if row['completed']:
            return self.finisher.query(operation_id, request_wire)
        reply = self._query_remote(operation_id, request_wire)
        self._receive(operation_id, reply)
        return reply

    def reconcile_pending(self):
        return tuple(self.recover(operation_id) for operation_id in self.journal.pending())

    def _unsupported(self, *args, **kwargs):
        raise ContractError('ordinary coordinator does not implement lifecycle/restore/override')

    bootstrap_genesis = acquire_owner_lease = transfer_owner = verify_restore = activate_restore = override = _unsupported
