"""Author-owned opening-to-mutation fixtures, with no admission or real I/O."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

from app.control_plane.r1_validation import ChainBoundary
from app.control_plane.r1_validation_codec import c2, decode, h2, obj, sha
from tests.r1_validation_fixtures import build_world
from tests.r1_validation_restore_fixtures import manifest, members_for


def append_mutation(current, decision="COMMIT", *, checkpoint=None, owner=None, fault=None, offset=20000):
    """Append a new actually signed V2 operation to a verified opening source."""
    source = current.source
    snapshot = decode(source.snapshot_wire)
    material = next(item for item in current.deployments
        if item.storage_generation_id == snapshot["storage_generation_id"]
        and item.control_plane_generation_id == snapshot["control_plane_generation_id"])
    parent = SimpleNamespace(root=current.root, receipt_key=current.receipt_key, pin=current.pin,
        deployment=material, authority=decode(source.history.authority_history),
        core=decode(source.history.core_histories[0].raw),
        request={"intent":{"identity":snapshot["identity"],"scope":{"trust_domain_id":source.chain_boundary.trust_domain_id}}})
    world = build_world(decision, parent=parent, initial_checkpoint=checkpoint or current.after,
        identity=snapshot["identity"], id_offset=offset, time_offset=snapshot["captured_at"]+100,
        actor_identity=owner or snapshot["owner_identity"], faults=fault)
    after, opening = world.objects["after"], source.opening
    inventory = decode(source.inventory_wire)
    inventory["entries"].append({"operation_id":world.request["intent"]["operation_id"],"wire_version":2,
        "request_raw_sha256":sha(c2(world.request)),"authorization_raw_sha256":sha(c2(world.objects["authorization"])),
        "terminal_ref":after["authority_ref"],"audit_ref":after["audit_ref"],"state":world.objects["receipt"]["result_state"]})
    inventory["entries"].sort(key=lambda entry:entry["operation_id"])
    profile={"history_version":2,"profile":"ALIGNED_OPENING","authority_tip":after["authority_ref"],
        "actual_core_audit_tip":after["audit_ref"],"actual_core_state_version":after["state_version"],
        "completion_digest":sha(c2(world.objects["completion"]))}
    one=lambda role:next(member.raw for member in source.members if member.role==role)
    members=members_for(world,opening,inventory,one("SIGNED_ORIGIN"),one("SOURCE_DEPLOYMENT"),one("SOURCE_FENCING"),profile)
    snapshot.update(authority_tip=after["authority_ref"],audit_tip=after["audit_ref"],state_version=after["state_version"],
        operation_inventory_digest=h2(inventory),history_archive_digest=h2(manifest(members)),
        captured_at=world.objects["completion"]["completed_at"]+100)
    boundary=replace(source.chain_boundary,expected_end_checkpoint_wire=c2(after))
    result=replace(source,snapshot_wire=c2(snapshot),inventory_wire=c2(inventory),manifest_wire=c2(manifest(members)),
        members=members,history=world.evidence(),chain_boundary=boundary,
        source_deployment_observation=replace(source.source_deployment_observation,
            authority_tip_wire=c2(after["authority_ref"]),audit_tip_wire=c2(after["audit_ref"]),state_version=after["state_version"]),
        source_fencing_observation=replace(source.source_fencing_observation,
            authority_tip_wire=c2(after["authority_ref"]),audit_tip_wire=c2(after["audit_ref"]),observed_at=snapshot["captured_at"]-1))
    return SimpleNamespace(source=result,trust=current.trust,deployments=current.deployments,pin=current.pin,
        root=current.root,receipt_key=current.receipt_key,after=after,mutation=world,opening_checkpoint=current.after)


def altered_opening(current, *, generation_delta=0, authority_sequence=None, authority_hash=None, audit_hash=None):
    """Re-sign opening and recompute every dependent archive/boundary hash."""
    from app.control_plane.r1_validation import CoreHistory, HistoryEvidence
    from app.control_plane.r1_validation_crypto import FixedTrust
    from app.control_plane.r1_validation_codec import s2
    from tests.r1_validation_fixtures import registry

    source=current.source; opening=source.opening
    pin=deepcopy(current.pin)
    pin["authority_generation"]+=generation_delta
    trust=FixedTrust(c2(pin),current.trust.root_public_key)
    def sign(value):
        field="root_signature" if "root_signature" in value else "receipt_signature"
        value[field]=(current.root if field=="root_signature" else current.receipt_key).sign(s2(value)).hex()
        return value
    auth=decode(opening.authorization_wire)
    auth.update(target_authority_generation=pin["authority_generation"],trust_config_digest=h2(pin))
    sign(auth)
    candidate=decode(opening.audit_wire)["candidate"]
    candidate["opening_authorization_digest"]=h2(auth)
    if audit_hash is not None: candidate["previous_audit_ref"]["audit_hash"]=audit_hash
    ack=decode(opening.prepare_wire)
    ack.update(opening_authorization_digest=h2(auth),audit_candidate_digest=h2(candidate),target_authority_generation=pin["authority_generation"])
    sign(ack)
    receipt=decode(opening.receipt_wire)
    receipt.update(opening_authorization_digest=h2(auth),opening_prepare_digest=h2(ack),audit_candidate_digest=h2(candidate),authority_generation=pin["authority_generation"])
    if authority_sequence is not None: receipt["authority_sequence"]=authority_sequence
    if authority_hash is not None: receipt["previous_authority_ref"]["receipt_hash"]=authority_hash
    sign(receipt)
    audit=obj("audit_record",candidate=candidate,receipt_digest=h2(receipt))
    checkpoint=obj("local_checkpoint",state_version=auth["state_version"],
        authority_ref=obj("authority_ref",wire_version=2,authority_generation=pin["authority_generation"],authority_sequence=receipt["authority_sequence"],receipt_hash=h2(receipt)),
        audit_ref=obj("audit_ref",wire_version=2,audit_sequence=candidate["audit_sequence"],audit_hash=h2(audit)))
    binding=decode(opening.initializer_binding_wire);binding["trust_config_digest"]=h2(pin)
    opening=replace(opening,authorization_wire=c2(auth),prepare_wire=c2(ack),receipt_wire=c2(receipt),audit_wire=c2(audit),initializer_binding_wire=c2(binding))
    material=next(item for item in current.deployments if item.core_installation_id==auth["core_installation_id"])
    authority,core=registry(pin),registry(pin,material)
    inventory=decode(source.inventory_wire)
    inventory.update(authority_generation=pin["authority_generation"],entries=[{"operation_id":auth["opening_id"],"wire_version":2,
        "request_raw_sha256":sha(c2(auth)),"authorization_raw_sha256":sha(c2(auth)),"terminal_ref":checkpoint["authority_ref"],
        "audit_ref":checkpoint["audit_ref"],"state":"COMMITTED"}])
    snapshot=decode(source.snapshot_wire)
    snapshot.update(source_authority_generation=pin["authority_generation"],authority_tip=checkpoint["authority_ref"],audit_tip=checkpoint["audit_ref"],operation_inventory_digest=h2(inventory))
    profile={"history_version":2,"profile":"ALIGNED_OPENING","authority_tip":checkpoint["authority_ref"],
        "actual_core_audit_tip":checkpoint["audit_ref"],"actual_core_state_version":checkpoint["state_version"],"completion_digest":None}
    replacements={"AUTHORITY_PIN":trust.pin_wire,"OPENING_AUTHORIZATION":c2(auth),"OPENING_PREPARE":c2(ack),
        "AUTHORITY_RECEIPT":c2(receipt),"CORE_AUDIT":c2(audit),"INITIALIZER_ADMISSION":c2(binding),
        "OPERATION_INVENTORY":c2(inventory),"SOURCE_PROFILE":c2(profile),"AUTHORITY_REGISTRY":c2(authority),"CORE_REGISTRY":c2(core)}
    old_headers={source.history.authority_history:authority,source.history.core_histories[0].raw:core}
    header_replacements={c2(decode(raw)["header"]):c2(value["header"]) for raw,value in old_headers.items()}
    members=tuple(replace(member,raw=replacements.get(member.role,header_replacements.get(member.raw,member.raw))) for member in source.members)
    snapshot["history_archive_digest"]=h2(manifest(members))
    result=replace(source,snapshot_wire=c2(snapshot),inventory_wire=c2(inventory),manifest_wire=c2(manifest(members)),members=members,opening=opening,
        history=HistoryEvidence((),c2(authority),(CoreHistory(material.runtime_principal,c2(core)),)),
        chain_boundary=replace(source.chain_boundary,start_checkpoint_wire=c2(checkpoint),expected_end_checkpoint_wire=c2(checkpoint)),
        source_deployment_observation=replace(source.source_deployment_observation,authority_pin_wire=trust.pin_wire,
            authority_tip_wire=c2(checkpoint["authority_ref"]),audit_tip_wire=c2(checkpoint["audit_ref"])),
        source_fencing_observation=replace(source.source_fencing_observation,authority_tip_wire=c2(checkpoint["authority_ref"]),audit_tip_wire=c2(checkpoint["audit_ref"])))
    return SimpleNamespace(source=result,trust=trust,deployments=current.deployments,pin=pin,root=current.root,receipt_key=current.receipt_key,after=checkpoint)
