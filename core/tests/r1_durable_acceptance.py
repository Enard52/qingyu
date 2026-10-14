"""Executable Slice04 acceptance probes against one owned initialized resource."""
from pathlib import Path
import hashlib
import json

from app.control_plane.r1_validation_codec import ContractError, decode, h2
from app.control_plane.r1_scoped_transport import ScopedTransportUncertain, ScopedHTTPRejected
from tests.r1_durable_run import core, request_for, service, start_server


def stop(child, output):
    if child.poll() is None:
        child.terminate()
    child.wait(timeout=15)
    output.close()


def run(config_path):
    path = Path(config_path).resolve()
    results = {'resource': path.parent.name, 'controlled_provider_instantiated': False}

    # Ordinary product replay across a full online process restart.
    child, output = start_server(path)
    try:
        coordinator = core(path, create=not (path.parent / 'finish.sqlite').exists())
        request, source = request_for(path, coordinator, 'COMMIT', 'restart-roundtrip')
        first = coordinator.governed_mutation(request, source)
        op = first.operation_id
        wire = first.result_wire
    finally:
        stop(child, output)
    child, output = start_server(path)
    try:
        reopened = core(path)
        replay = reopened.governed_mutation(request, source)
        assert replay.result_wire == wire and replay.applied is False
        results['process_restart_replay'] = {'operation_id': op,
            'result_sha256': hashlib.sha256(wire).hexdigest(), 'same_bytes': True}
    finally:
        stop(child, output)

    # Grant commits, server exits before returning bytes, then retry returns the
    # exact stored signed object and completes the original operation.
    coordinator = core(path)
    request, source = request_for(path, coordinator, 'COMMIT', 'lost-grant-response')
    op = coordinator.persist_intent(request, source)
    child, output = start_server(path, 'after_grant_commit')
    try:
        try:
            coordinator.recover(op)
            raise AssertionError('grant response loss expected')
        except ScopedTransportUncertain:
            pass
        child.wait(timeout=15)
    finally:
        stop(child, output)
    _, provider = service(path)
    before = provider.query_current_issue('GRANT', op)
    child, output = start_server(path)
    try:
        completed = core(path).recover(op)
    finally:
        stop(child, output)
    after = provider.query_current_issue('GRANT', op)
    assert before == after
    results['lost_grant_response'] = {'operation_id': op,
        'signed_object_sha256': hashlib.sha256(before).hexdigest(),
        'exact_replay': True, 'completed': decode(completed.result_wire)['result_state']}

    # Permit uses the same durable issue path after terminal commit.
    coordinator = core(path)
    request, source = request_for(path, coordinator, 'ABORT', 'lost-permit-response')
    op = coordinator.persist_intent(request, source)
    child, output = start_server(path, 'after_permit_commit')
    try:
        try:
            coordinator.recover(op)
            raise AssertionError('permit response loss expected')
        except ScopedTransportUncertain:
            pass
        child.wait(timeout=15)
    finally:
        stop(child, output)
    _, provider = service(path)
    before = provider.query_current_issue('PERMIT', op)
    child, output = start_server(path)
    try:
        completed = core(path).recover(op)
    finally:
        stop(child, output)
    after = provider.query_current_issue('PERMIT', op)
    assert before == after
    results['lost_permit_response'] = {'operation_id': op,
        'signed_object_sha256': hashlib.sha256(before).hexdigest(),
        'exact_replay': True, 'completed': decode(completed.result_wire)['result_state']}

    # Revoke-before-action rejects the action.  Runtime supplies neither the
    # revocation authorization nor the registry caller binding.
    child, output = start_server(path)
    try:
        coordinator = core(path)
        request, source = request_for(path, coordinator, 'COMMIT', 'revoke-before-action')
        op = coordinator.persist_intent(request, source)
        coordinator.source.ensure_execution(request, source)
        _, provider = service(path)
        grant_wire = provider.query_current_issue('GRANT', op)
        grant_digest = h2(decode(grant_wire))
        revoke_sequence = provider.revoke('GRANT_REVOKE', grant_digest,
            b'fixed-operator-authorization:revoke-before-action',
            verify_operator=lambda wire, kind, digest, now: True)
        try:
            coordinator.client.prepare(request, source)
            raise AssertionError('revoked grant acted')
        except ScopedHTTPRejected as exc:
            assert exc.status == 409
        results['revoke_before_action'] = {'operation_id': op,
            'revocation_sequence': revoke_sequence, 'action_rejected': True}
    finally:
        stop(child, output)

    # Action-before-revoke remains an immutable historical fact; the later
    # revoke has a strictly greater Authority event position and blocks the
    # next action rather than rewriting PREPARE.
    child, output = start_server(path)
    try:
        coordinator = core(path)
        request, source = request_for(path, coordinator, 'COMMIT', 'action-before-revoke')
        op = coordinator.persist_intent(request, source)
        coordinator.source.ensure_execution(request, source)
        reply = coordinator.client.prepare(request, source)
        assert reply.state == 'PREPARED'
        prepare_sequence = max(decode(w)['position']['event_sequence']
                               for w in reply.authority.event_wires
                               if decode(w)['event_kind'] == 'PREPARE')
        _, provider = service(path)
        grant_wire = provider.query_current_issue('GRANT', op)
        revoke_sequence = provider.revoke('GRANT_REVOKE', h2(decode(grant_wire)),
            b'fixed-operator-authorization:action-before-revoke',
            verify_operator=lambda wire, kind, digest, now: True)
        assert revoke_sequence > prepare_sequence
        results['action_before_revoke'] = {'operation_id': op,
            'prepare_sequence': prepare_sequence,
            'revocation_sequence': revoke_sequence, 'history_preserved': True}
    finally:
        stop(child, output)

    return results


if __name__ == '__main__':
    import sys
    result = run(sys.argv[1])
    print(json.dumps(result, indent=2, sort_keys=True))
