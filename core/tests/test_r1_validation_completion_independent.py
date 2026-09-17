"""Non-author product checks using independently constructed histories.

No product or author helper generates the fixtures. Recorded public inputs and
expected outcomes can be replayed; ephemeral private keys are never recorded.
"""
from copy import deepcopy
from dataclasses import asdict, fields, is_dataclass, replace
import json
import unittest

from app.control_plane.r1_validation import (
    validate_evidence, validate_source_evidence, validate_restoration_evidence,
)
from app.control_plane.r1_validation_codec import ContractError
from app.control_plane.r1_validation_crypto import verify_signed
from app.control_plane._r1_validation_restore import ArchiveMember
from r1_validation_completion_independent_fixtures import (
    IndependentHistory, establish_genesis, source_evidence, restore_case, restored_final_source, partial_restore_case, generation_after_restore, wire, h, raw, sha, sign, typed,
)


OBSERVATIONS = []
PUBLIC_INPUT_BLOBS = {}


def describe(value):
    if type(value) is bytes:
        key=sha(value)
        PUBLIC_INPUT_BLOBS[key]=value.hex()
        return {"bytes":len(value),"sha256":key}
    if is_dataclass(value):
        return {"dataclass":type(value).__name__,"fields":{field.name:describe(getattr(value,field.name)) for field in fields(value) if field.init}}
    if type(value) is dict:return {k:describe(v) for k,v in value.items()}
    if type(value) in (list,tuple):return [describe(v) for v in value]
    return value


def check_all_supplied_signatures(evidence, trust, proofs=()):
    """Independent traversal: no mutation/rebinding product helper used."""
    seen=set()
    def visit(value):
        if type(value) is dict:
            if "root_signature" in value or "receipt_signature" in value:
                content=wire(value)
                if content not in seen:
                    verify_signed(content,trust);seen.add(content)
            for child in value.values():visit(child)
        elif type(value) is list:
            for child in value:visit(child)
    for content in (*evidence.request_wires,evidence.authority_history,*(c.raw for c in evidence.core_histories),*evidence.context_wires):
        visit(json.loads(content))
    for proof in proofs:
        for content in (proof.context_wire,proof.source.opening.authorization_wire,proof.source.opening.prepare_wire,proof.source.opening.receipt_wire):visit(json.loads(content))
    return len(seen)


def inspect(label,expected,evidence,trust,deployments,*,boundary=None,proofs=(),operation="COMPLETION_HISTORY",verify_signatures=True):
    original=describe(dict(evidence=evidence,trust=trust,deployments=deployments,boundary=boundary,proofs=proofs))
    signature_count=check_all_supplied_signatures(evidence,trust,proofs) if verify_signatures else None
    try:
        result=validate_evidence(operation,evidence,trust,deployments,chain_boundary=boundary,restore_evidence=proofs)
        actual,detail="ACCEPT",asdict(result)
    except Exception as exc:
        actual,detail="REJECT",dict(error=type(exc).__name__,message=str(exc))
    row=dict(label=label,expected=expected,actual=actual,details=detail,independently_checked_real_signature_count=signature_count,
             input=original,input_unchanged=original==describe(dict(evidence=evidence,trust=trust,deployments=deployments,boundary=boundary,proofs=proofs)))
    OBSERVATIONS.append(row)
    return row


def run_case(label,expected,case,**kwargs):
    return inspect(label,expected,case["evidence"],case["trust"],case["deployments"],boundary=case["chain_boundary"],proofs=case["restore_evidence"],**kwargs)


def inspect_source(label,expected,source,trust,deployments,*,proof=None):
    original=describe(dict(source=source,trust=trust,deployments=deployments,proof=proof))
    try:
        result=(validate_source_evidence(source,trust,deployments) if proof is None else validate_restoration_evidence(proof,trust,deployments))
        actual,detail="ACCEPT",describe(asdict(result))
    except Exception as exc:actual,detail="REJECT",dict(error=type(exc).__name__,message=str(exc))
    row=dict(label=label,expected=expected,actual=actual,details=detail,input=original,
             input_unchanged=original==describe(dict(source=source,trust=trust,deployments=deployments,proof=proof)))
    OBSERVATIONS.append(row);return row


class IndependentCompletionTests(unittest.TestCase):
    def outcome(self,row):
        self.assertEqual(row["actual"],row["expected"],row["details"])
        self.assertTrue(row["input_unchanged"])
        if row["actual"]=="REJECT":self.assertIn(row["details"]["error"],("ContractError","MissingTrustedContext","UnsupportedOperation"))
        else:
            self.assertEqual(row["details"]["history_origin"],"UNVERIFIED")
            self.assertEqual(row["details"]["current_eligibility"],"NOT_EVALUATED")

    def test_independent_variable_length_and_identity_commit_abort_chains(self):
        for seed,decisions in ((71001,["COMMIT"]),(72200,["COMMIT","ABORT"]),(74650,["ABORT","COMMIT","ABORT","COMMIT"])):
            with self.subTest(seed=seed):
                world=IndependentHistory(seed,initial_state=11)
                for decision in decisions:world.add_operation(decision)
                evidence,trust,deployments=world.product_inputs()
                self.outcome(inspect("independent_chain_"+str(seed),"ACCEPT",evidence,trust,deployments,boundary=world.boundary()))
                self.assertEqual(world.cursor["state_version"],11+decisions.count("COMMIT"))
                self.assertEqual(world.cursor["authority_ref"]["authority_sequence"],7+len(decisions))
                self.assertEqual(world.cursor["audit_ref"]["audit_sequence"],12+len(decisions))

    def test_independent_signed_second_operation_reuses_old_checkpoint(self):
        world=IndependentHistory(75000);world.add_operation();world.add_operation("ABORT",request_checkpoint=world.start)
        evidence,trust,deployments=world.product_inputs()
        row=inspect("signed_consistent_second_operation_stale_checkpoint","REJECT",evidence,trust,deployments,boundary=world.boundary())
        self.outcome(row);self.assertEqual(row["independently_checked_real_signature_count"],10)
        self.assertIn("checkpoint",row["details"]["message"])

    def test_independent_signed_cross_identity_history_splice(self):
        world=IndependentHistory(76000);world.add_operation()
        world.identity=deepcopy(world.identity);world.identity["continuity_id"]=world.uid(9000)
        world.add_operation("ABORT")
        evidence,trust,deployments=world.product_inputs()
        self.outcome(inspect("signed_cross_identity_history","REJECT",evidence,trust,deployments,boundary=world.boundary()))

    def test_external_checkpoint_tail_and_boundary_are_required(self):
        world=IndependentHistory(77000);world.add_operation();world.add_operation("ABORT")
        evidence,trust,deployments=world.product_inputs()
        self.outcome(inspect("multi_operation_missing_external_boundary","REJECT",evidence,trust,deployments))
        self.outcome(inspect("external_expected_tail_is_not_archive_claim","REJECT",evidence,trust,deployments,
                             boundary=replace(world.boundary(),expected_end_checkpoint_wire=wire(world.start))))

    def test_same_operation_same_content_replay_and_conflicting_content(self):
        world=IndependentHistory(78000);world.add_operation();world.add_operation("ABORT")
        evidence,trust,deployments=world.product_inputs()
        self.outcome(inspect("identical_request_duplicate","ACCEPT",replace(evidence,request_wires=evidence.request_wires+(evidence.request_wires[0],)),trust,deployments,boundary=world.boundary()))
        conflict=deepcopy(world.requests[0]);conflict["intent"]["payload"]["value"]=9800
        self.outcome(inspect("same_operation_conflicting_request","REJECT",replace(evidence,request_wires=evidence.request_wires+(wire(conflict),)),trust,deployments,boundary=world.boundary()))

    def test_independent_aligned_and_history_only_restore_sources(self):
        for seed,aligned in ((81001,True),(81502,False)):
            with self.subTest(aligned=aligned):
                world=IndependentHistory(seed);establish_genesis(world);world.add_operation("COMMIT",apply=aligned)
                case=restore_case(world)
                self.outcome(run_case("independent_restore_"+("aligned" if aligned else "history_only_tail"),"ACCEPT",case))
                snapshot=json.loads(case["source"].snapshot_wire)
                self.assertEqual(snapshot["audit_tip"]["audit_sequence"],2 if aligned else 1)
                self.assertEqual(snapshot["authority_tip"]["authority_sequence"],2)

    def test_independent_multi_operation_restore_from_actual_mid_backup(self):
        world=IndependentHistory(82000);establish_genesis(world);world.add_operation("COMMIT");world.add_operation("ABORT")
        case=restore_case(world,backup_count=1)
        self.outcome(run_case("independent_two_operation_restore_mid_backup","ACCEPT",case))
        self.assertEqual(len(case["restored"]),1)

    def test_genesis_only_source_and_backup_already_at_tail(self):
        for count in (0,2):
            with self.subTest(operation_count=count):
                world=IndependentHistory(82500+count);establish_genesis(world)
                for decision in ["COMMIT","ABORT"][:count]:world.add_operation(decision)
                source=source_evidence(world);_,trust,deployments=world.product_inputs()
                self.outcome(inspect_source("independent_source_count_"+str(count),"ACCEPT",source,trust,deployments))
                case=restore_case(world,source=source,backup_count=count)
                self.outcome(inspect_source("independent_backup_at_tail_"+str(count),"ACCEPT",source,trust,case["deployments"],proof=case["restore_evidence"][0]))
                self.assertEqual(case["restored"],[])

    def test_real_signed_context_and_source_identity_mismatch(self):
        world=IndependentHistory(83000);establish_genesis(world);world.add_operation(apply=False)
        def wrong(context):context["source_snapshot"]["identity"]["continuity_id"]=world.uid(9901)
        case=restore_case(world,context_fault=wrong)
        row=run_case("signed_digest_rebound_restore_source_identity_mismatch","REJECT",case)
        self.outcome(row);self.assertGreaterEqual(row["independently_checked_real_signature_count"],10)

    def test_real_signed_permit_points_to_wrong_target(self):
        world=IndependentHistory(84000);establish_genesis(world);world.add_operation(apply=False)
        def wrong(target):target["storage_generation_id"]=world.uid(9902)
        self.outcome(run_case("signed_issuance_and_local_use_wrong_target","REJECT",restore_case(world,target_fault=wrong)))

    def test_archive_member_bytes_missing_member_and_extra_member(self):
        for kind in ("missing","rawbytes","extra"):
            with self.subTest(kind=kind):
                world=IndependentHistory(85000+len(kind));establish_genesis(world);world.add_operation(apply=False)
                source=source_evidence(world);members=list(source.members)
                if kind=="missing":members=[m for m in members if m.role!="PREPARE_ACK"]
                elif kind=="rawbytes":
                    index=next(i for i,m in enumerate(members) if m.role=="SOURCE_FENCING")
                    members[index]=replace(members[index],raw=b"changed original bytes")
                else:members.append(ArchiveMember("SOURCE_REQUEST",1,b"{}"));members.sort(key=lambda m:(m.role,m.index))
                # Missing/extra declarations are internally self-consistent;
                # rawbytes deliberately retains the original declared hash.
                if kind!="rawbytes":
                    manifest=typed("archive_manifest",entries=[dict(role=m.role,index=m.index,byte_length=len(m.raw),sha256=sha(m.raw)) for m in members])
                    snapshot=json.loads(source.snapshot_wire);snapshot["history_archive_digest"]=h(manifest)
                    source=replace(source,manifest_wire=wire(manifest),snapshot_wire=wire(snapshot))
                source=replace(source,members=tuple(members))
                self.outcome(run_case("archive_"+kind,"REJECT",restore_case(world,source=source)))

    def test_backup_and_external_checkpoint_mismatch(self):
        world=IndependentHistory(86000);establish_genesis(world);world.add_operation(apply=False)
        case=restore_case(world)
        bad=replace(case["restore_evidence"][0],expected_backup_checkpoint_wire=wire(world.cursor))
        case["restore_evidence"]=(bad,)
        self.outcome(run_case("backup_cannot_supply_its_own_external_checkpoint","REJECT",case))

    def test_supplied_fencing_and_deployment_facts_must_match_original_source(self):
        world=IndependentHistory(87000);establish_genesis(world);world.add_operation(apply=False)
        source=source_evidence(world);_,trust,deployments=world.product_inputs()
        bad_fences=(
            ("wrong_head",replace(source.source_fencing_observation,authority_tip_wire=wire(world.start["authority_ref"]))),
            ("later_observation",replace(source.source_fencing_observation,observed_at=json.loads(source.snapshot_wire)["captured_at"]+1)),
            ("active_writer",replace(source.source_fencing_observation,core_writer_state="ACTIVE")),
            ("pending_operation",replace(source.source_fencing_observation,pending_operation_ids=(world.uid(8888),))),
        )
        for label,observed in bad_fences:
            with self.subTest(label=label):
                self.outcome(inspect_source("source_fencing_"+label,"REJECT",replace(source,source_fencing_observation=observed),trust,deployments))
        self.outcome(inspect_source("source_deployment_wrong_installation","REJECT",replace(source,source_deployment_observation=
                     replace(source.source_deployment_observation,core_installation_id=world.uid(8899))),trust,deployments))

    def test_supplied_origin_observations_cannot_come_from_other_target(self):
        world=IndependentHistory(88000);establish_genesis(world);world.add_operation(apply=False)
        source=source_evidence(world);_,trust,deployments=world.product_inputs()
        bad=replace(source,observed_origin=replace(source.observed_origin,external_storage_identity=world.uid(9999)))
        self.outcome(inspect_source("valid_root_origin_other_observed_storage","REJECT",bad,trust,deployments))

    def test_independent_restore_completion_final_source_then_generation_opening(self):
        world=IndependentHistory(89000);establish_genesis(world);world.add_operation("COMMIT",apply=False)
        case=restore_case(world);final_source=restored_final_source(case)
        self.outcome(inspect_source("independent_restored_target_final_source","ACCEPT",final_source,case["trust"],case["deployments"]))
        self.outcome(inspect_source("restored_final_source_missing_original_restore_proof","REJECT",
                                   replace(final_source,restoration_evidence=()),case["trust"],case["deployments"]))
        for label,options,expected in (("generation_after_real_restore",{},"ACCEPT"),("skip_generation",{"generation_increment":2},"REJECT"),
                                       ("wrong_independent_audit_predecessor",{"wrong_audit_previous":True},"REJECT")):
            with self.subTest(label=label):
                source,trust,deployments=generation_after_restore(case,final_source,**options)
                for content in (source.opening.authorization_wire,source.opening.prepare_wire,source.opening.receipt_wire):verify_signed(content,trust)
                row=inspect_source(label,expected,source,trust,deployments)
                row["current_opening_real_signatures_valid_before_semantics"]=3
                self.outcome(row)

    def test_partial_restored_target_is_history_only_and_cannot_open_generation(self):
        world=IndependentHistory(90000);establish_genesis(world);world.add_operation("COMMIT");world.add_operation("ABORT",apply=False)
        case=partial_restore_case(restore_case(world),1);source=restored_final_source(case)
        row=inspect_source("partly_completed_restore_target_source","ACCEPT",source,case["trust"],case["deployments"])
        self.outcome(row);self.assertEqual(row["details"]["profile"],"HISTORY_ONLY_TAIL")
        later,trust,deployments=generation_after_restore(case,source)
        self.outcome(inspect_source("partly_restored_source_must_not_open_generation","REJECT",later,trust,deployments))


if __name__ == "__main__":unittest.main()
