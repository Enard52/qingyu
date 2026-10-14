"""Actual public opening-to-mutation tests; this is author testing, not review."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.control_plane.r1_validation import validate_evidence, validate_source_evidence
from app.control_plane.r1_validation_codec import ContractError, c2, decode, sha
from app.control_plane.r1_validation_crypto import FixedTrust, verify_signed
from tests.r1_validation_legacy_fixtures import build_legacy_source
from tests.r1_validation_restore_fixtures import build_restore_world, lineage_source
from tests.r1_validation_opening_chain_fixtures import append_mutation, altered_opening


class OpeningMutationChainTests(unittest.TestCase):
    def previous(self, kind):
        if kind=="V1_TO_V2": return build_legacy_source(("COMMIT","ABORT","COMMIT"),offset=50000)
        full=build_restore_world(aligned=True)
        w=full.world
        return SimpleNamespace(source=full.proof.source,trust=w.trust,deployments=(w.deployment,),
            pin=w.pin,root=w.root,receipt_key=w.receipt_key)

    def verify(self, current):
        return validate_source_evidence(current.source,current.trust,current.deployments)

    def test_real_v1_bridge_then_commit_or_abort_and_public_completion(self):
        previous=self.previous("V1_TO_V2")
        old=decode(previous.source.snapshot_wire)
        for decision in ("COMMIT","ABORT"):
            with self.subTest(decision=decision):
                opening=lineage_source(previous,"V1_TO_V2",offset=10000)
                current=append_mutation(opening,decision)
                result=self.verify(current)
                after=decode(result.verified_checkpoint_wire)
                self.assertEqual(after["authority_ref"]["authority_generation"],1)
                self.assertEqual(after["authority_ref"]["authority_sequence"],old["authority_tip"]["authority_sequence"]+2)
                self.assertEqual(after["audit_ref"]["audit_sequence"],old["audit_tip"]["audit_sequence"]+2)
                self.assertEqual(after["state_version"],old["state_version"]+(decision=="COMMIT"))
                receipt=current.mutation.objects["receipt"]
                self.assertEqual(receipt["previous_authority_ref"],opening.after["authority_ref"])
                self.assertEqual(current.mutation.request["intent"]["scope"]["expected_audit_ref"],opening.after["audit_ref"])
                self.assertEqual(current.pin["api_version"],previous.pin["api_version"])
                completion=validate_evidence("COMPLETION_HISTORY",current.source.history,current.trust,current.deployments,
                                            chain_boundary=current.source.chain_boundary)
                self.assertEqual(len(completion.completion_digests),1)
                self.assertEqual((result.history_origin,result.current_eligibility),("UNVERIFIED","NOT_EVALUATED"))

    def test_generation_then_mutation_then_next_generation_keeps_audit_chain(self):
        previous=self.previous("GENERATION_RESTORE")
        original=decode(previous.source.snapshot_wire)
        for offset,decision in ((10000,"COMMIT"),(20000,"ABORT")):
            opening=lineage_source(previous,"GENERATION_RESTORE",offset=offset)
            current=append_mutation(opening,decision,offset=offset+50000)
            result=self.verify(current)
            after=decode(result.verified_checkpoint_wire)
            prior=decode(previous.source.snapshot_wire)
            self.assertEqual(after["authority_ref"]["authority_generation"],prior["source_authority_generation"]+1)
            self.assertEqual(after["authority_ref"]["authority_sequence"],2)
            self.assertEqual(after["audit_ref"]["audit_sequence"],prior["audit_tip"]["audit_sequence"]+2)
            self.assertEqual(after["state_version"],prior["state_version"]+(decision=="COMMIT"))
            validate_evidence("COMPLETION_HISTORY",current.source.history,current.trust,current.deployments,
                              chain_boundary=current.source.chain_boundary)
            previous=current
        self.assertEqual(after["audit_ref"]["audit_sequence"],original["audit_tip"]["audit_sequence"]+4)
        self.assertEqual(after["state_version"],original["state_version"]+1)

    def test_true_signed_wrong_generation_and_opening_receipt_sequence_rejected(self):
        for kind in ("V1_TO_V2","GENERATION_RESTORE"):
            good=lineage_source(self.previous(kind),kind,offset=10000)
            cases=(dict(generation_delta=1),dict(authority_sequence=good.after["authority_ref"]["authority_sequence"]+1))
            for change in cases:
                with self.subTest(kind=kind,change=change):
                    bad=altered_opening(good,**change)
                    for wire in (bad.source.opening.authorization_wire,bad.source.opening.prepare_wire,bad.source.opening.receipt_wire):
                        verify_signed(wire,bad.trust)
                    current=append_mutation(bad)
                    with self.assertRaises(ContractError): self.verify(current)

    def test_true_signed_wrong_authority_or_audit_opening_predecessor_rejected(self):
        for kind in ("V1_TO_V2","GENERATION_RESTORE"):
            good=lineage_source(self.previous(kind),kind,offset=10000)
            for change in (dict(authority_hash="a"*64),dict(audit_hash="b"*64)):
                with self.subTest(kind=kind,change=change):
                    bad=altered_opening(good,**change)
                    verify_signed(bad.source.opening.receipt_wire,bad.trust)
                    with self.assertRaises(ContractError): self.verify(append_mutation(bad))

    def test_new_mutation_cannot_skip_actual_opening_checkpoint(self):
        for kind in ("V1_TO_V2","GENERATION_RESTORE"):
            opening=lineage_source(self.previous(kind),kind,offset=10000)
            for field,hashfield in (("authority_ref","receipt_hash"),("audit_ref","audit_hash")):
                before=deepcopy(opening.after);before[field][hashfield]="c"*64
                with self.subTest(kind=kind,field=field):
                    current=append_mutation(opening,checkpoint=before)
                    verify_signed(current.mutation.objects["receipt"],current.trust)
                    with self.assertRaisesRegex(ContractError,"chain missing predecessor"):
                        self.verify(current)

    def test_mutation_owner_and_true_signed_opening_owner_cannot_change(self):
        for kind in ("V1_TO_V2","GENERATION_RESTORE"):
            previous=self.previous(kind)
            for where in ("opening","mutation"):
                with self.subTest(kind=kind,where=where):
                    opening=lineage_source(previous,kind,offset=10000,fault="owner" if where=="opening" else None)
                    current=append_mutation(opening,owner="forged-owner" if where=="mutation" else None)
                    verify_signed(current.mutation.objects["receipt"],current.trust)
                    with self.assertRaises(ContractError): self.verify(current)

    def test_supplied_archive_and_key_cannot_replace_external_fixed_key(self):
        for kind in ("V1_TO_V2","GENERATION_RESTORE"):
            current=append_mutation(lineage_source(self.previous(kind),kind,offset=10000))
            other=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
            pin={**current.pin,"receipt_public_key":other.hex(),"receipt_key_id":sha(other)}
            trust=FixedTrust(c2(pin),current.trust.root_public_key)
            with self.subTest(kind=kind),self.assertRaises(ContractError):
                validate_source_evidence(current.source,trust,current.deployments)


if __name__=="__main__": unittest.main()
