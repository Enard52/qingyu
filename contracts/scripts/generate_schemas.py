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
    identity_path = SCHEMA_DIR / "core-identity-v1.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    envelope = identity["properties"]["IdentityContinuityEnvelope"]["properties"]
    uuid4_pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    for field in ("qingyu_identity_id", "continuity_id"):
        envelope[field]["pattern"] = uuid4_pattern
    alias_uuid_pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    envelope["continuity_alias"]["not"] = {"pattern": alias_uuid_pattern}
    identity_path.write_text(
        json.dumps(identity, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
