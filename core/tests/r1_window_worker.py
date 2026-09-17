"""Owned spawned workers; all arguments contain public test evidence only."""
import os
import traceback

from tests.r1_window_fixtures import input_for, open_window_service


def run_window_worker(path, sequence, operation, action, send, *, crash_at=None,
                      ready=None, release=None, barrier_at=None, now=None):
    from tests.r1_window_observation import observe_calls
    calls, restore_observer = observe_calls()
    try:
        once = False
        def hook(stage):
            nonlocal once
            if stage == barrier_at and not once:
                once = True
                ready.set()
                if not release.wait(120):
                    raise TimeoutError("owned boundary worker synchronization deadline")
            if stage == crash_at:
                send.send({"crash_boundary": stage, "pid": os.getpid(), "ordinal": operation.ordinal,
                           "validation_calls": calls})
                send.close()
                os._exit(83)
        service = open_window_service(path, sequence, operation, hook=hook, now=now)
        if action == "finish":
            result = service.finish(input_for(sequence, operation))
        elif action == "recover":
            result = service.recover(operation.operation_id)
        elif action == "query":
            result = service.query(operation.operation_id, operation.request_wire)
        else:
            raise ValueError("unknown controlled worker action")
        send.send({"ok": True, "pid": os.getpid(), "ordinal": operation.ordinal, "result": result,
                   "validation_calls": calls})
    except BaseException as exc:
        send.send({"ok": False, "pid": os.getpid(), "ordinal": operation.ordinal,
                   "error_type": type(exc).__name__, "error": str(exc), "traceback": traceback.format_exc(),
                   "validation_calls": calls})
    finally:
        restore_observer()
        send.close()
