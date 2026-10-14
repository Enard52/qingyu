"""Transparent call observation: the real validator and its result are unchanged."""
from app.control_plane._r1_validation_stream import BoundedHistory


def observe_calls():
    calls = []
    original = BoundedHistory.append
    def observed(self, window, *args, **kwargs):
        try:
            result = original(self, window, *args, **kwargs)
        except Exception as exc:
            calls.append({"outcome": "REJECT", "explicit_request_wires": len(window.request_wires),
                          "error_type": type(exc).__name__, "error": str(exc)})
            raise
        calls.append({"outcome": "ACCEPT", **{key: result[key] for key in (
            "window", "revision", "distinct_operation_count", "cumulative_requests", "authority_positions",
            "core_positions", "continuation_source", "operation_ids")}})
        return result
    BoundedHistory.append = observed
    def restore():
        BoundedHistory.append = original
    return calls, restore
