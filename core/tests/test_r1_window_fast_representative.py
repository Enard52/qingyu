from __future__ import annotations

from pathlib import Path
import tempfile

from app.control_plane.r1_validation import FixedTrust
from tests.r1_window_fixtures import generate_sequence, window_evidence, boundary_for, open_window_service, WindowSource, input_for


def test_fast_representative_window_subset_accepts_16_operations():
    """FAST / REPRESENTATIVE only; this is not the 129-operation long acceptance."""
    sequence = generate_sequence(16)
    engine = __import__('app.control_plane._r1_validation_stream', fromlist=['BoundedHistory']).BoundedHistory(
        FixedTrust(sequence.pin_wire, sequence.root_public_key),
        (sequence.deployment,),
        boundary_for(sequence, sequence.operations),
    )
    engine.append(window_evidence(sequence, sequence.operations, completed=True), operation="COMPLETION_HISTORY")
    root = Path("<repo>/core-r1-implementation/.tmp/r1-window-fast-representative")
    root.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="fast-window-", dir=root)) / "fast.sqlite3"
    service = open_window_service(path, sequence, sequence.operations[0], create=True)
    for op in sequence.operations:
        service.source = WindowSource(sequence, op)
        result = service.finish(input_for(sequence, op))
        assert result.operation_id == op.operation_id
    with service.store.transaction(write=False) as db:
        assert db.execute("SELECT count(*) FROM completions").fetchone()[0] == 16
