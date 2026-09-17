"""Spawn-only workers for Slice 02's explicitly owned temporary databases."""
import os
import traceback
from dataclasses import replace

from tests.r1_atomic_finish_fixtures import SyntheticSource, finish_input, open_finisher


def run_worker(path, case, action, send, *, crash_at=None, ready=None, release=None,
               now=None, barrier_at=None):
    """No inherited open SQLite connection, no serialized issuer private key."""
    try:
        if type(case.trust) is tuple:
            from app.control_plane.r1_validation_crypto import FixedTrust
            case = replace(case, trust=FixedTrust(*case.trust))
        def hook(label):
            if label == barrier_at:
                ready.set()
                if not release.wait(30):
                    raise TimeoutError("owned test worker synchronization deadline")
            if label == crash_at:
                send.send({"crash_boundary": label, "pid": os.getpid()})
                send.close()
                os._exit(83)
        service = open_finisher(path, case, source=SyntheticSource(case, now=now), hook=hook)
        if action == "finish":
            result = service.finish(finish_input(case))
        elif action == "persist":
            result = service.persist(finish_input(case))
        elif action == "recover":
            result = service.recover(case.operation_id)
        elif action == "query":
            result = service.query(case.operation_id, case.request_wire)
        else:
            raise ValueError("unknown test worker action")
        send.send({"ok": True, "pid": os.getpid(), "result": result})
    except BaseException as exc:
        send.send({"ok": False, "pid": os.getpid(), "error_type": type(exc).__name__,
                   "error": str(exc), "traceback": traceback.format_exc()})
    finally:
        send.close()
