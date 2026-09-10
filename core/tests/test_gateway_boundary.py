from __future__ import annotations

import ast
from pathlib import Path


def test_core_has_no_gateway_python_imports():
    root = Path(__file__).parents[1]
    forbidden = {"gateway", "gateway.app", "gateway.models"}
    for path in (root / "app").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(alias.name not in forbidden and not alias.name.startswith("gateway.") for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert node.module is None or not node.module.startswith("gateway")
