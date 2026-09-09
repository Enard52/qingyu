import hashlib
import copy
from dataclasses import dataclass
from typing import Any
from sqlalchemy import or_, select
from sqlalchemy.orm import Session
from ..models import ArchiveObject, Conversation, ImportBatchCommit, ImportJob, Message, MessageObservation, MessageRevision, SourceAccount
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

class ImportService:
    """Persist fixture conversations in short, ownership-fenced transactions."""
    def __init__(self, db: Session): self.db = db

    def import_fixture(self, payload: dict[str, Any], archive_object_id, platform="fixture", account_label="default", job: ImportJob | None = None, lease_token=None, source_member="fixture.json", parser=None, unknown_entries=None, health_check=None) -> ImportOutcome:
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
        try:
            for conv_index, parsed in enumerate(parser.parse(payload)):
                health_check()
                ImportWorker(self.db).assert_ownership(job, lease_token)
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
                    _merge_report(report, existing_batch.report_delta)
                    self.db.commit()
                    if not ImportWorker(self.db).advance_checkpoint(job, lease_token, sequence_no, batch_key):
                        raise LeaseLost("ownership_lost")
                    continue

                before = copy.deepcopy(report)
                if synthetic:
                    report["unknown"].append({"type": "missing_external_conversation_id", "severity": "warning", "conversation_identity": external_id, "detail": "generated deterministic synthetic identity", "archive_object_id": str(archive_object_id), "zip_member": source_member, "raw_pointer": f"/conversations/{conv_index}"})
                conversation = self.db.scalar(select(Conversation).where(Conversation.source_account_id == account_id, Conversation.external_conversation_id == external_id))
                if conversation is None:
                    conversation = Conversation(source_account_id=account_id, external_conversation_id=external_id, title=parsed.title, metadata_json={"identity_kind": "synthetic" if synthetic else "external"}); self.db.add(conversation); self.db.flush(); report["conversations"]["new"] += 1
                elif conversation.title != parsed.title:
                    conversation.title = parsed.title; report["conversations"]["changed"] += 1
                else: report["conversations"]["existing"] += 1
                resolved, revisions = {}, {}
                for item in parsed.messages:
                    message = self.db.scalar(select(Message).where(Message.conversation_id == conversation.id, Message.external_message_id == item.node_id))
                    if message is None:
                        message = Message(conversation_id=conversation.id, external_message_id=item.node_id); self.db.add(message); self.db.flush(); report["messages"]["new"] += 1
                    else: report["messages"]["existing"] += 1
                    digest = compute_text_hash(item.content_text)
                    fingerprint = compute_revision_fingerprint(role=item.role, content_text=item.content_text, content_json=item.content_json, model=item.model, raw_timestamp=item.raw_timestamp, attachments=item.attachments)
                    revision = self.db.scalar(select(MessageRevision).where(MessageRevision.message_id == message.id, MessageRevision.revision_fingerprint == fingerprint))
                    if revision is None:
                        latest = self.db.scalar(select(MessageRevision).where(MessageRevision.message_id == message.id).order_by(MessageRevision.revision_no.desc()))
                        pointer = f"/conversations/{conv_index}/mapping/{json_pointer_escape(item.node_id)}"
                        revision = MessageRevision(message_id=message.id, revision_no=(latest.revision_no + 1 if latest else 1), role=item.role, content_text=item.content_text, content_json=item.content_json, model=item.model, raw_timestamp=item.raw_timestamp, content_hash=digest, revision_fingerprint=fingerprint, archive_object_id=archive_object_id, raw_json_pointer=pointer); self.db.add(revision); self.db.flush(); report["revisions"]["new"] += 1
                    else: report["revisions"]["existing"] += 1
                    resolved[item.node_id], revisions[item.node_id] = message, revision
                report["tree_anomalies"].extend(TreeValidator().validate(parsed.messages))
                for order, item in enumerate(parsed.messages):
                    if self.db.scalar(select(MessageObservation).where(MessageObservation.import_job_id == job.id, MessageObservation.external_node_id == item.node_id, MessageObservation.message_revision_id == revisions[item.node_id].id)): continue
                    parent = resolved.get(item.parent_node_id)
                    pointer = f"/conversations/{conv_index}/mapping/{json_pointer_escape(item.node_id)}"
                    self.db.add(MessageObservation(import_job_id=job.id, message_id=resolved[item.node_id].id, message_revision_id=revisions[item.node_id].id, external_node_id=item.node_id, external_parent_node_id=item.parent_node_id, parent_message_id=parent.id if parent else None, branch_key=item.branch_key, is_current_path=item.node_id == parsed.current_node_id, observation_order=order, raw_mapping_pointer=pointer, metadata_json={"archive_object_id": str(archive.id), "zip_member": source_member}))
                health_check()
                ImportWorker(self.db).assert_ownership(job, lease_token)
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
                if not ImportWorker(self.db).advance_checkpoint(job, lease_token, sequence_no, batch_key):
                    raise LeaseLost("ownership_lost")
            report["items"] = {"conversations": sum(report["conversations"].values()), "messages": sum(report["messages"].values())}
            counts = {"items_discovered": report["items"]["messages"], "items_imported": report["messages"]["new"], "discovered_count": report["items"]["messages"], "imported_count": report["messages"]["new"], "skipped_count": report["messages"]["existing"], "failed_count": report["messages"]["failed"]}
        except Exception:
            self.db.rollback()
            raise
        return ImportOutcome(report=report, counts=counts)


def json_pointer_escape(value: str) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


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


def _merge_report(target: dict, delta: dict) -> None:
    for section in ("conversations", "messages", "revisions", "attachments"):
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
