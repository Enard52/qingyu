"""Generate checked JSON Schema artifacts from the public contract models."""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
sys.path.insert(0, str(ROOT / "src"))

from qingyu_contracts.evidence import (  # noqa: E402
    AttachmentObservationPage,
    EvidenceCapability,
    EvidenceErrorResponse,
    EvidenceRef,
    NodePage,
    ObservationPage,
)
from qingyu_contracts.identity import IdentityContinuityEnvelope  # noqa: E402


def write_schema(filename: str, title: str, models: list[type]) -> None:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": title,
        "type": "object",
        "properties": {
            model.__name__: model.model_json_schema(ref_template="#/$defs/{model}")
            for model in models
        },
        "required": [model.__name__ for model in models],
        "additionalProperties": False,
    }
    (SCHEMA_DIR / filename).write_text(
        json.dumps(schema, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    write_schema(
        "evidence-query-v1.json",
        "Qingyu Gateway Evidence Query API v1",
        [
            ObservationPage,
            NodePage,
            AttachmentObservationPage,
            EvidenceRef,
            EvidenceCapability,
            EvidenceErrorResponse,
        ],
    )
    write_schema(
        "core-identity-v1.json",
        "Qingyu Core Identity Contract v1",
        [IdentityContinuityEnvelope],
    )


if __name__ == "__main__":
    main()
