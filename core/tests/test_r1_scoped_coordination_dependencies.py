"""Author dependency selection checks using the real bounded kernel.

Only original requests/admission and initial FENCES_SET facts are built here.
No Ack, FIX, terminal, completion or remote service is manufactured.
"""
from pathlib import Path
import tempfile
import unittest
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app._r1_coordination_journal import CoordinationJournal
from app.r1_scoped_coordinator import ScopedCoreCoordinator, build_mutation_request
from app.control_plane import _r1_validation_semantics as sem
from app.control_plane._r1_validation_stream import BoundedHistory, WindowEvidence, registry_slice
from app.control_plane.r1_validation import ChainBoundary, DeploymentEvidence
from app.control_plane.r1_validation_codec import ContractError, c2, decode, h2, obj, record, sha
from app.control_plane.r1_validation_crypto import FixedTrust


def uid(number):
    return str(UUID(int=number))


class OriginalDependencyChecks(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='r1-s03-author-dependencies-')
        self.journal = CoordinationJournal.create(Path(self.folder.name) / 'journal.sqlite',
            scope_wire=b'owned original scope', checkpoint_wire=b'owned original checkpoint')
        receipt, root, tls = (Ed25519PrivateKey.generate().public_key() for _ in range(3))
        receipt_wire, root_wire = (k.public_bytes(Encoding.Raw, PublicFormat.Raw) for k in (receipt, root))
        tls_wire = tls.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.pin = obj('authority_pin', authority_domain_id=uid(1), authority_instance_id=uid(2),
            authority_generation=1, receipt_public_key=receipt_wire.hex(), receipt_key_id=sha(receipt_wire),
            api_version=2, https_origin='https://localhost:8443', server_spki_sha256=sha(tls_wire), operator_root_key_id=sha(root_wire))
        self.trust = FixedTrust(c2(self.pin), root_wire)
        self.material = DeploymentEvidence('owned-core', uid(3), uid(4), uid(5), b'owned-deployment', b'owned-component', tls_wire)
        self.identity = obj('identity', qingyu_identity_id=uid(6), continuity_id=uid(7), genesis_operation_id=uid(8))
        self.checkpoint = obj('local_checkpoint', state_version=4,
            authority_ref=obj('authority_ref', wire_version=2, authority_generation=1, authority_sequence=4, receipt_hash='a' * 64),
            audit_ref=obj('audit_ref', wire_version=2, audit_sequence=4, audit_hash='b' * 64))
        self.boundary = ChainBoundary(c2(self.identity), c2(self.checkpoint), c2(self.checkpoint),
            'owned-caller', 1, 1, uid(4), uid(5), uid(9))

    def tearDown(self):
        self.folder.cleanup()

    def engine(self):
        return BoundedHistory(self.trust, (self.material,), self.boundary)

    def inputs(self, count, *, persisted=None):
        authority = {'header': sem.header(self.pin), 'events': [], 'records': {}}
        originals = []
        for index in range(count):
            scope = obj('requested_scope', trust_domain_id=uid(9), authority_domain_id=uid(1),
                authority_instance_id=uid(2), authority_generation=1, actor_identity='owned-caller',
                owner_version=1, continuity_epoch=1, expected_state_version=4, storage_generation_id=uid(4),
                control_plane_generation_id=uid(5), lease_id=uid(20), lease_generation=1,
                caller_runtime_id=uid(21), session_id=uid(22), capability='core_governance',
                expected_authority_ref=self.checkpoint['authority_ref'], expected_audit_ref=self.checkpoint['audit_ref'])
            wire = build_mutation_request(identity=self.identity, scope=scope,
                payload={'operation_id': uid(999999), 'value': index}, mutation_id=f'original-{index}', decision='COMMIT',
                created_at=1000, operation_id=uid(100 + index), local_commit_id=uid(1000 + index), source_authorization_id=uid(2000 + index))
            request = decode(wire); intent = request['intent']; material = self.material
            source = record('source_admission', operation_id=intent['operation_id'], intent_digest=h2(intent),
                source_decision_digest=h2(request['source_decision']), identity_digest=h2(self.identity), scope_digest=h2(scope),
                **{name: scope[name] for name in ('actor_identity', 'caller_runtime_id', 'session_id', 'lease_id', 'lease_generation')},
                admitted_at=1000, session_issued_at=900, session_expires_at=2000, lease_issued_at=900, lease_expires_at=2000,
                normal_business_admission=True, core_installation_id=material.core_installation_id,
                deployment_admission_digest=sha(material.deployment_bytes), component_artifact_digest=sha(material.component_bytes),
                trust_config_digest=h2(self.pin))
            source_wire = c2(source)
            fence = record('fence_state', history_version=2, operation_id=intent['operation_id'],
                fences=sem.expected_fences(request), barrier_operation_id=intent['operation_id'], unresolved_operation_ids=[intent['operation_id']])
            digest = sem.rawhash(fence); authority['records'][digest] = fence
            authority['events'].append(record('registry_event', history_version=2,
                position=sem.position(authority), recorded_at=1000, event_kind='FENCES_SET', input_digest=digest, output_digest=None))
            originals.append((wire, source_wire))
            if persisted is None or index < persisted:
                with self.journal.transaction() as db:
                    db.execute('INSERT INTO attempts(operation_id,mutation_id,local_commit_id,request_wire,source_wire) VALUES(?,?,?,?,?)',
                        (intent['operation_id'], intent['mutation_id'], intent['local_commit_id'], wire, source_wire))
        return originals, WindowEvidence((originals[0][0],), registry_slice(authority), (), source_admission_wires=(originals[0][1],))

    def test_peer_originals_restore_complete_prefix_without_creating_business_fact(self):
        originals, window = self.inputs(2)
        with self.assertRaisesRegex(ContractError, 'window event lacks original request'):
            self.engine().append(window, operation='REGISTRY_RELATIONS')
        before = self.journal.inspect()
        engine = self.engine()
        with self.journal.transaction(write=False) as db:
            complete = ScopedCoreCoordinator._with_original_dependencies(db, engine, window)
        self.assertEqual(complete.request_wires, tuple(v[0] for v in originals))
        self.assertEqual(complete.source_admission_wires, tuple(v[1] for v in originals))
        result = engine.append(complete, operation='REGISTRY_RELATIONS')
        self.assertEqual(result['distinct_operation_count'], 2)
        self.assertEqual(set(engine.authority_state['phase'].values()), {'ABSENT'})
        self.assertFalse(engine.authority_state['acks'] or engine.authority_state['fixes'] or engine.authority_state['terminals'])
        self.assertEqual(before, self.journal.inspect())

    def test_remote_peer_without_same_journal_original_is_rejected_without_writes(self):
        _, window = self.inputs(2, persisted=1)
        before = self.journal.inspect()
        with self.journal.transaction(write=False) as db:
            with self.assertRaisesRegex(ContractError, 'locally persisted admitted original'):
                ScopedCoreCoordinator._with_original_dependencies(db, self.engine(), window)
        self.assertEqual(before, self.journal.inspect())

    def test_all_65_referenced_originals_are_retained_and_original_bound_rejects(self):
        _, window = self.inputs(65)
        engine = self.engine()
        with self.journal.transaction(write=False) as db:
            complete = ScopedCoreCoordinator._with_original_dependencies(db, engine, window)
        self.assertEqual(len(complete.request_wires), 65)
        self.assertEqual(len(complete.authority.event_wires), 65)
        with self.assertRaisesRegex(ContractError, 'operation chain resource limit'):
            engine.append(complete, operation='REGISTRY_RELATIONS')

    def test_64_referenced_originals_pass_the_actual_kernel_bound(self):
        _, window = self.inputs(64)
        engine = self.engine()
        with self.journal.transaction(write=False) as db:
            complete = ScopedCoreCoordinator._with_original_dependencies(db, engine, window)
        result = engine.append(complete, operation='REGISTRY_RELATIONS')
        self.assertEqual(result['distinct_operation_count'], 64)
        self.assertEqual(len(engine.requests), 64)
        self.assertFalse(engine.authority_state['terminals'])


if __name__ == '__main__':
    unittest.main()
