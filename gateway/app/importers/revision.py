import hashlib, json
from typing import Any

def build_revision_payload(*, role, content_text, content_json, model, raw_timestamp):
    return {"role": role, "content_text": content_text, "content_json": content_json, "model": model, "raw_timestamp": raw_timestamp}

def canonical_revision_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)

def compute_revision_fingerprint(**kwargs) -> str:
    return hashlib.sha256(canonical_revision_json(build_revision_payload(**kwargs)).encode("utf-8")).hexdigest()

def compute_text_hash(text: str | None) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()
