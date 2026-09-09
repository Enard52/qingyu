from __future__ import annotations

from dataclasses import dataclass
import mimetypes
from pathlib import Path
import stat

from ..archive.service import ArchiveIntegrityError, ArchiveService, PreparedObject
from .generic import ParsedAttachment, ParsedConversation


@dataclass(frozen=True)
class AttachmentWork:
    parsed: ParsedAttachment
    availability: str
    prepared: PreparedObject | None = None
    error_code: str | None = None
    observed_filename: str | None = None
    observed_media_type: str | None = None
    observed_size_bytes: int | None = None


def prepare_attachment_work(
    conversations: tuple[ParsedConversation, ...],
    extract_root: Path,
    archive_service: ArchiveService,
    *,
    source_platform: str,
    source_member: str,
    health_check,
) -> dict[tuple[int, str, str], AttachmentWork]:
    """Classify declarations and publish available bytes without DB writes."""
    root = extract_root.resolve(strict=True)
    regular_members: dict[str, Path] = {}
    unsafe_members: set[str] = set()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for candidate in extract_root.rglob("*"):
        relative = candidate.relative_to(extract_root).as_posix()
        details = candidate.lstat()
        is_reparse = stat.S_ISLNK(details.st_mode) or bool(
            getattr(details, "st_file_attributes", 0) & reparse_flag
        )
        if is_reparse:
            unsafe_members.add(relative)
        elif candidate.is_file():
            regular_members[relative] = candidate
    result = {}
    for conversation_index, conversation in enumerate(conversations):
        for message in conversation.messages:
            for attachment in message.attachments:
                health_check()
                key = (conversation_index, message.node_id, attachment.stable_attachment_key)
                if attachment.member_path is None:
                    result[key] = AttachmentWork(attachment, "referenced_only")
                    continue
                member_parts = Path(attachment.member_path).parts
                member_ancestors = {
                    Path(*member_parts[:index]).as_posix()
                    for index in range(1, len(member_parts) + 1)
                }
                if member_ancestors & unsafe_members:
                    result[key] = AttachmentWork(attachment, "failed", error_code="unsafe_attachment_member")
                    continue
                source = regular_members.get(attachment.member_path)
                if source is None:
                    result[key] = AttachmentWork(attachment, "missing")
                    continue
                observed_size = source.stat().st_size
                observed_media_type = mimetypes.guess_type(source.name)[0] or "application/octet-stream"
                observed = {
                    "observed_filename": source.name,
                    "observed_media_type": observed_media_type,
                    "observed_size_bytes": observed_size,
                }
                if attachment.size_bytes is not None and attachment.size_bytes != observed_size:
                    result[key] = AttachmentWork(
                        attachment, "failed", error_code="attachment_size_mismatch", **observed
                    )
                    continue
                if (
                    attachment.media_type is not None
                    and attachment.media_type.strip().lower() != observed_media_type.lower()
                ):
                    result[key] = AttachmentWork(
                        attachment, "failed", error_code="attachment_media_type_mismatch", **observed
                    )
                    continue
                try:
                    prepared = archive_service.prepare(
                        source,
                        source.name,
                        source_platform,
                        observed_media_type,
                        logical_path=attachment.member_path,
                        observation_metadata={
                            "source_member": source_member,
                            "attachment_member_path": attachment.member_path,
                            "raw_json_pointer": attachment.raw_json_pointer,
                            "declared_filename": attachment.filename,
                            "declared_media_type": attachment.media_type,
                            "declared_size_bytes": attachment.size_bytes,
                        },
                    )
                except (ArchiveIntegrityError, OSError, ValueError) as exc:
                    result[key] = AttachmentWork(
                        attachment,
                        "failed",
                        error_code=type(exc).__name__,
                        **observed,
                    )
                else:
                    result[key] = AttachmentWork(
                        attachment, "available", prepared=prepared, **observed
                    )
    return result
