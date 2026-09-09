import copy
from dataclasses import dataclass, replace
from typing import Any
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from ..archive.service import ArchiveIntegrityError, ArchiveService, PendingArchiveResult
from ..models import ArchiveObject, ArchiveObservation, Attachment, AttachmentObservation, Conversation, ImportBatchCommit, ImportJob, Message, MessageObservation, MessageRevision, SourceAccount
from .attachments import AttachmentWork
from .generic import GenericTreeParser
from .report import empty_report
from .tree import TreeValidator
from .worker import ImportWorker, LeaseLost, LeaseRequired
from .revision import compute_revision_fingerprint, compute_text_hash


@dataclass(frozen=True)
class ImportOutcome:
    report: dict
    counts: dict


class BatchReplayIdentityError(RuntimeError):
    pass


class AttachmentPersistenceError(RuntimeError):
    def __init__(self, key, parsed):
        super().__init__("attachment_persistence_failed")
        self.key = key
        self.parsed = parsed

class ImportService:
    """Persist fixture conversations in short, ownership-fenced transactions."""
    def __init__(self, db: Session): self.db = db

    def import_fixture(self, payload: dict[str, Any], archive_object_id, platform="fixture", account_label="default", job: ImportJob | None = None, lease_token=None, source_member="fixture.json", parser=None, unknown_entries=None, health_check=None, parsed_conversations=None, attachment_work=None, attachment_archive: ArchiveService | None = None) -> ImportOutcome:
        health_check = health_check or (lambda: None)
        if job is None or lease_token is None:
            raise LeaseRequired("lease_required")
        account = self.db.get(SourceAccount, job.source_account_id)
        if account is None:
            raise ValueError("invalid_source_account")
        archive = self.db.get(ArchiveObject, job.archive_object_id)
        if archive is None:
            raise ValueError("archive_object_missing")
        archive_object_id = archive.id
        account_id = account.id
        archive_sha256 = archive.sha256
        report = empty_report(GenericTreeParser.name, GenericTreeParser.version, "matched")
        report["unknown"].extend(unknown_entries or [])
        parser = parser or GenericTreeParser()
        parsed_conversations = (
            tuple(parsed_conversations)
            if parsed_conversations is not None
            else parser.parse(payload)
        )
        attachment_work = attachment_work or {}
        attempt_number = int(job.attempt_count)
        try:
            for conv_index, parsed in enumerate(parsed_conversations):
                health_check()
                owned_job = ImportWorker(self.db).assert_ownership(job, lease_token)
                attempt_number = int(owned_job.attempt_count)
                if any(message.attachments for message in parsed.messages) and attempt_number <= 0:
                    raise ValueError("invalid_attempt_number")
                self.db.scalar(select(SourceAccount.id).where(SourceAccount.id == account_id).with_for_update())
                external_id = parsed.external_id
                synthetic = not bool(external_id)
                if synthetic:
                    external_id = f"synthetic:{archive_sha256}:{source_member}:conversation:{conv_index}"
                sequence_no = conv_index + 1
                batch_key = f"{source_member}:conversation:{conv_index}"
                existing_batch = self.db.scalar(
                    select(ImportBatchCommit).where(
                        ImportBatchCommit.import_job_id == job.id,
                        or_(ImportBatchCommit.sequence_no == sequence_no, ImportBatchCommit.batch_key == batch_key),
                    )
                )
                if existing_batch is not None:
                    _validate_replay(existing_batch, sequence_no, batch_key, external_id, parser.name, parser.version)
                    _merge_report(report, existing_batch.report_delta, include_attachments=False)

                before = copy.deepcopy(report)
                if synthetic and existing_batch is None:
                    report["unknown"].append({"type": "missing_external_conversation_id", "severity": "warning", "conversation_identity": external_id, "detail": "generated deterministic synthetic identity", "archive_object_id": str(archive_object_id), "zip_member": source_member, "raw_pointer": f"/conversations/{conv_index}"})
                conversation = self.db.scalar(select(Conversation).where(Conversation.source_account_id == account_id, Conversation.external_conversation_id == external_id))
                if conversation is None:
                    if existing_batch is not None:
                        raise BatchReplayIdentityError("batch_replay_conversation_missing")
                    conversation = Conversation(source_account_id=account_id, external_conversation_id=external_id, title=parsed.title, metadata_json={"identity_kind": "synthetic" if synthetic else "external"}); self.db.add(conversation); self.db.flush(); report["conversations"]["new"] += 1
                elif existing_batch is not None:
                    pass
                elif conversation.title != parsed.title:
                    conversation.title = parsed.title; report["conversations"]["changed"] += 1
                else: report["conversations"]["existing"] += 1
                resolved, revisions = {}, {}
                for item in parsed.messages:
                    message = self.db.scalar(select(Message).where(Message.conversation_id == conversation.id, Message.external_message_id == item.node_id))
                    if message is None:
                        if existing_batch is not None:
                            raise BatchReplayIdentityError("batch_replay_message_missing")
                        message = Message(conversation_id=conversation.id, external_message_id=item.node_id); self.db.add(message); self.db.flush(); report["messages"]["new"] += 1
                    elif existing_batch is None: report["messages"]["existing"] += 1
                    digest = compute_text_hash(item.content_text)
                    fingerprint = compute_revision_fingerprint(role=item.role, content_text=item.content_text, content_json=item.content_json, model=item.model, raw_timestamp=item.raw_timestamp, attachments=item.attachments)
                    revision = self.db.scalar(select(MessageRevision).where(MessageRevision.message_id == message.id, MessageRevision.revision_fingerprint == fingerprint))
                    if revision is None:
                        if existing_batch is not None:
                            raise BatchReplayIdentityError("batch_replay_revision_missing")
                        latest = self.db.scalar(select(MessageRevision).where(MessageRevision.message_id == message.id).order_by(MessageRevision.revision_no.desc()))
                        pointer = f"/conversations/{conv_index}/mapping/{json_pointer_escape(item.node_id)}"
                        revision = MessageRevision(message_id=message.id, revision_no=(latest.revision_no + 1 if latest else 1), role=item.role, content_text=item.content_text, content_json=item.content_json, model=item.model, raw_timestamp=item.raw_timestamp, content_hash=digest, revision_fingerprint=fingerprint, archive_object_id=archive_object_id, raw_json_pointer=pointer); self.db.add(revision); self.db.flush(); report["revisions"]["new"] += 1
                    elif existing_batch is None: report["revisions"]["existing"] += 1
                    resolved[item.node_id], revisions[item.node_id] = message, revision
                if existing_batch is None:
                    report["tree_anomalies"].extend(TreeValidator().validate(parsed.messages))
                    for order, item in enumerate(parsed.messages):
                        if self.db.scalar(select(MessageObservation).where(MessageObservation.import_job_id == job.id, MessageObservation.external_node_id == item.node_id, MessageObservation.message_revision_id == revisions[item.node_id].id)): continue
                        parent = resolved.get(item.parent_node_id)
                        pointer = f"/conversations/{conv_index}/mapping/{json_pointer_escape(item.node_id)}"
                        self.db.add(MessageObservation(import_job_id=job.id, message_id=resolved[item.node_id].id, message_revision_id=revisions[item.node_id].id, external_node_id=item.node_id, external_parent_node_id=item.parent_node_id, parent_message_id=parent.id if parent else None, branch_key=item.branch_key, is_current_path=item.node_id == parsed.current_node_id, observation_order=order, raw_mapping_pointer=pointer, metadata_json={"archive_object_id": str(archive.id), "zip_member": source_member}))

                pending_archives = []
                declared_work = []
                for item in parsed.messages:
                    for declared in item.attachments:
                        key = (conv_index, item.node_id, declared.stable_attachment_key)
                        work = attachment_work.get(key)
                        if work is None:
                            work = AttachmentWork(declared, "referenced_only")
                        declared_work.append((key, item, work))
                declared_work.sort(key=lambda entry: _attachment_lock_order(entry[2]))
                for key, item, work in declared_work:
                    try:
                        pending = self._persist_attachment(
                            job=job,
                            attempt_number=attempt_number,
                            revision=revisions[item.node_id],
                            work=work,
                            source_member=source_member,
                            archive_service=attachment_archive,
                        )
                    except (ArchiveIntegrityError, OSError) as exc:
                        raise AttachmentPersistenceError(key, work.parsed) from exc
                    if pending is not None:
                        pending_archives.append(pending)
                    report["attachments"][work.availability] += 1
                health_check()
                ImportWorker(self.db).assert_ownership(job, lease_token)
                if existing_batch is None:
                    delta = _report_delta(before, report)
                    delta_counts = _counts_from_report(delta)
                    self.db.add(ImportBatchCommit(
                        import_job_id=job.id,
                        conversation_id=conversation.id,
                        sequence_no=sequence_no,
                        batch_key=batch_key,
                        external_conversation_id=external_id,
                        parser_name=parser.name,
                        contract_version=parser.version,
                        report_delta=delta,
                        counts_delta=delta_counts,
                    ))
                self.db.commit()
                for pending in pending_archives:
                    attachment_archive.finalize(pending)
                batch_has_failed_attachment = any(
                    work.availability == "failed" for _key, _item, work in declared_work
                )
                if not batch_has_failed_attachment and not ImportWorker(self.db).advance_checkpoint(
                    job, lease_token, sequence_no, batch_key
                ):
                    raise LeaseLost("ownership_lost")
                if batch_has_failed_attachment:
                    break
            report["attachments"] = self._attachment_counts(job.id, attempt_number)
            report["items"] = {"conversations": sum(report["conversations"].values()), "messages": sum(report["messages"].values())}
            counts = {"items_discovered": report["items"]["messages"], "items_imported": report["messages"]["new"], "discovered_count": report["items"]["messages"], "imported_count": report["messages"]["new"], "skipped_count": report["messages"]["existing"], "failed_count": report["messages"]["failed"]}
        except AttachmentPersistenceError as exc:
            self.db.rollback()
            retry_work = dict(attachment_work)
            retry_work[exc.key] = AttachmentWork(
                exc.parsed,
                "failed",
                error_code="attachment_archive_failed",
            )
            return self.import_fixture(
                payload,
                archive_object_id,
                platform=platform,
                account_label=account_label,
                job=job,
                lease_token=lease_token,
                source_member=source_member,
                parser=parser,
                unknown_entries=unknown_entries,
                health_check=health_check,
                parsed_conversations=parsed_conversations,
                attachment_work=retry_work,
                attachment_archive=attachment_archive,
            )
        except Exception:
            self.db.rollback()
            raise
        return ImportOutcome(report=report, counts=counts)

    def _persist_attachment(self, *, job, attempt_number, revision, work, source_member, archive_service):
        declared = work.parsed
        attachment = self.db.scalar(
            select(Attachment).where(
                Attachment.message_revision_id == revision.id,
                Attachment.stable_attachment_key == declared.stable_attachment_key,
            )
        )
        stable_values = (
            declared.external_attachment_id,
            declared.original_reference,
            declared.filename,
            declared.media_type,
            declared.size_bytes,
            declared.descriptor_json,
        )
        if attachment is None:
            attachment = Attachment(
                message_revision_id=revision.id,
                stable_attachment_key=declared.stable_attachment_key,
                external_attachment_id=declared.external_attachment_id,
                original_reference=declared.original_reference,
                filename=declared.filename,
                media_type=declared.media_type,
                size_bytes=declared.size_bytes,
                descriptor_json=declared.descriptor_json,
            )
            self.db.add(attachment)
            self.db.flush()
        elif stable_values != (
            attachment.external_attachment_id,
            attachment.original_reference,
            attachment.filename,
            attachment.media_type,
            attachment.size_bytes,
            attachment.descriptor_json,
        ):
            raise BatchReplayIdentityError("attachment_identity_mismatch")

        existing = self.db.scalar(
            select(AttachmentObservation).where(
                AttachmentObservation.import_job_id == job.id,
                AttachmentObservation.attempt_number == attempt_number,
                AttachmentObservation.attachment_id == attachment.id,
            )
        )
        if existing is not None:
            if existing.availability != work.availability:
                raise BatchReplayIdentityError("attachment_observation_replay_mismatch")
            if work.availability == "available":
                if work.prepared is None or archive_service is None or existing.archive_object_id is None:
                    raise BatchReplayIdentityError("attachment_observation_replay_mismatch")
                record = self.db.get(ArchiveObject, existing.archive_object_id)
                provenance = self.db.scalar(
                    select(ArchiveObservation).where(
                        ArchiveObservation.import_job_id == job.id,
                        ArchiveObservation.archive_object_id == existing.archive_object_id,
                        ArchiveObservation.metadata_json["stable_attachment_key"].astext
                        == declared.stable_attachment_key,
                        ArchiveObservation.metadata_json["attempt_number"].astext
                        == str(attempt_number),
                        ArchiveObservation.metadata_json["raw_json_pointer"].astext
                        == declared.raw_json_pointer,
                    ).order_by(ArchiveObservation.id)
                )
                if (
                    record is None
                    or provenance is None
                    or record.sha256 != work.prepared.sha256
                    or record.size_bytes != work.prepared.size_bytes
                    or record.relative_path != work.prepared.relative_path
                ):
                    raise BatchReplayIdentityError("attachment_archive_replay_mismatch")
                return PendingArchiveResult(
                    prepared=work.prepared,
                    object_id=record.id,
                    observation_id=provenance.id,
                    record=record,
                    observation=provenance,
                )
            return None

        pending = None
        if work.availability == "available":
            if work.prepared is None:
                raise ValueError("available_attachment_not_prepared")
            if archive_service is None:
                raise ValueError("attachment_archive_required")
            prepared = replace(
                work.prepared,
                observation_metadata={
                    **work.prepared.observation_metadata,
                    "stable_attachment_key": declared.stable_attachment_key,
                    "attempt_number": attempt_number,
                    "raw_json_pointer": declared.raw_json_pointer,
                },
            )
            pending = archive_service.persist_prepared(prepared, import_job_id=job.id)
        metadata = {"error_code": work.error_code} if work.error_code else {}
        self.db.add(AttachmentObservation(
            import_job_id=job.id,
            attempt_number=attempt_number,
            attachment_id=attachment.id,
            availability=work.availability,
            archive_object_id=pending.object_id if pending else None,
            source_member=source_member,
            attachment_member_path=declared.member_path,
            raw_json_pointer=declared.raw_json_pointer,
            observed_filename=work.observed_filename,
            observed_media_type=work.observed_media_type,
            observed_size_bytes=work.observed_size_bytes,
            metadata_json=metadata,
        ))
        return pending

    def _attachment_counts(self, job_id, attempt_number):
        counts = {key: 0 for key in ("available", "missing", "referenced_only", "failed")}
        rows = self.db.execute(
            select(AttachmentObservation.availability, func.count(AttachmentObservation.id))
            .where(
                AttachmentObservation.import_job_id == job_id,
                AttachmentObservation.attempt_number == attempt_number,
            )
            .group_by(AttachmentObservation.availability)
        ).all()
        for availability, count in rows:
            counts[availability] = int(count)
        return counts


def json_pointer_escape(value: str) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def _attachment_lock_order(work: AttachmentWork):
    """Acquire advisory locks in digest order to avoid cross-job deadlocks."""
    if work.prepared is not None:
        return (0, work.prepared.sha256, work.parsed.stable_attachment_key)
    return (1, "", work.parsed.stable_attachment_key)


def _validate_replay(batch, sequence_no, batch_key, external_id, parser_name, contract_version) -> None:
    identity = (
        batch.sequence_no,
        batch.batch_key,
        batch.external_conversation_id,
        batch.parser_name,
        batch.contract_version,
    )
    expected = (sequence_no, batch_key, external_id, parser_name, contract_version)
    if identity != expected:
        raise BatchReplayIdentityError("batch_replay_identity_mismatch")


def _report_delta(before: dict, after: dict) -> dict:
    delta = empty_report(after["parser"]["name"], after["parser"]["version"], after["parser"]["detection"])
    for section in ("conversations", "messages", "revisions", "attachments"):
        for key in delta[section]:
            delta[section][key] = after[section][key] - before[section][key]
    for section in ("tree_anomalies", "unknown", "errors"):
        delta[section] = copy.deepcopy(after[section][len(before[section]):])
    return delta


def _merge_report(target: dict, delta: dict, *, include_attachments: bool = True) -> None:
    for section in ("conversations", "messages", "revisions", "attachments"):
        if section == "attachments" and not include_attachments:
            continue
        for key, value in delta.get(section, {}).items():
            target[section][key] += value
    for section in ("tree_anomalies", "unknown", "errors"):
        target[section].extend(copy.deepcopy(delta.get(section, [])))


def _counts_from_report(report: dict) -> dict:
    messages = report["messages"]
    return {
        "discovered_count": sum(messages.values()),
        "imported_count": messages["new"],
        "skipped_count": messages["existing"] + messages["skipped"],
        "failed_count": messages["failed"],
    }
