from __future__ import annotations

import json
from pathlib import Path


def test_current_scope_is_non_authoritative_index_with_markdown_view():
    payload = json.loads(Path("current-scope.json").read_text(encoding="utf-8"))
    markdown = Path("docs/CURRENT_SCOPE.md").read_text(encoding="utf-8")

    assert payload["implementation_head"] in markdown
    assert payload["candidate_tag"] in markdown
    assert payload["current_state"]["implementation_gate"] == "BLOCKED"
    assert payload["current_state"]["foundation_closure"] == "NOT ENTERED"
    assert payload["current_state"]["slice05"] == "NOT STARTED"
    assert payload["conflict_precedence"][-1] == "CURRENT_SCOPE index"
    assert "not a source of authority" in markdown
