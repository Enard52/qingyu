import hashlib, json
from typing import Any

from .generic import ParsedAttachment, canonical_attachment_descriptor


def _fingerprint_attachment_descriptor(attachment: ParsedAttachment | dict[str, Any]) -> dict[str, Any]:
    if isinstance(attachment, ParsedAttachment):
        descriptor = dict(attachment.descriptor_json)
        stable_key = attachment.stable_attachment_key
    else:
        # canonical_attachment_descriptor deliberately allow-lists declared fields,
        # so observation/runtime keys supplied by callers cannot affect a revision.
        descriptor = json.loads(canonical_attachment_descriptor(attachment))
        stable_key = attachment.get("stable_attachment_key")
    if stable_key is not None:
        descriptor["stable_attachment_key"] = stable_key
    return descriptor


def build_revision_payload(*, role, content_text, content_json, model, raw_timestamp, attachments=()):
    payload = {"role": role, "content_text": content_text, "content_json": content_json, "model": model, "raw_timestamp": raw_timestamp}
    normalized_attachments = sorted(
        (_fingerprint_attachment_descriptor(item) for item in attachments),
        key=canonical_revision_json,
    )
    # Omitting this key for an empty collection preserves the exact legacy payload.
    if normalized_attachments:
        payload["attachments"] = normalized_attachments
    return payload

def canonical_revision_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)

def compute_revision_fingerprint(**kwargs) -> str:
    return hashlib.sha256(canonical_revision_json(build_revision_payload(**kwargs)).encode("utf-8")).hexdigest()

def compute_text_hash(text: str | None) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()
