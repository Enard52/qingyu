import hashlib
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..models import ArchiveObject, Conversation, ImportJob, Message, MessageObservation, MessageRevision, SourceAccount
from .generic import GenericTreeParser
from .report import empty_report
from .tree import TreeValidator
from .worker import ImportWorker, LeaseLost, LeaseRequired
from .revision import compute_revision_fingerprint, compute_text_hash

class ImportService:
    """Persist fixture conversations in short, ownership-fenced transactions."""
    def __init__(self, db: Session): self.db = db

    def import_fixture(self, payload: dict[str, Any], archive_object_id, platform="fixture", account_label="default", job: ImportJob | None = None, lease_token=None) -> ImportJob:
        created_job = job is None
        if job is not None:
            if job.status == "running" and lease_token is None:
                raise LeaseRequired("lease_required")
            account = self.db.get(SourceAccount, job.source_account_id)
            if account is None:
                raise ValueError("invalid_source_account")
            archive = self.db.get(ArchiveObject, job.archive_object_id)
            if archive is None:
                raise ValueError("archive_object_missing")
            archive_object_id = archive.id
        else:
            account = self.db.scalar(select(SourceAccount).where(SourceAccount.platform == platform, SourceAccount.account_label == account_label))
            if account is None:
                account = SourceAccount(platform=platform, account_label=account_label, metadata_json={}); self.db.add(account); self.db.flush()
        if job is None:
            job = ImportJob(source_account_id=account.id, archive_object_id=archive_object_id, parser_name=GenericTreeParser.name, parser_version=GenericTreeParser.version, status="running", report_json={})
            self.db.add(job); self.db.flush(); lease_token = job.lease_token
        archive = self.db.get(ArchiveObject, archive_object_id)
        if archive is None:
            raise ValueError("archive_object_missing")
        report = empty_report(GenericTreeParser.name, GenericTreeParser.version, "matched")
        try:
            for conv_index, parsed in enumerate(GenericTreeParser().parse(payload)):
                if lease_token is not None: ImportWorker(self.db).assert_ownership(job, lease_token)
                external_id = parsed.external_id
                synthetic = not bool(external_id)
                if synthetic:
                    external_id = f"synthetic:{archive.sha256}:conversation:{conv_index}"
                    report["unknown"].append({"type": "missing_external_conversation_id", "severity": "warning", "conversation_identity": external_id, "detail": "generated deterministic synthetic identity", "raw_pointer": f"/conversations/{conv_index}"})
                conversation = self.db.scalar(select(Conversation).where(Conversation.source_account_id == account.id, Conversation.external_conversation_id == external_id))
                if conversation is None:
                    conversation = Conversation(source_account_id=account.id, external_conversation_id=external_id, title=parsed.title, metadata_json={"identity_kind": "synthetic" if synthetic else "external"}); self.db.add(conversation); self.db.flush(); report["conversations"]["new"] += 1
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
                    fingerprint = compute_revision_fingerprint(role=item.role, content_text=item.content_text, content_json=item.content_json, model=item.model, raw_timestamp=item.raw_timestamp)
                    revision = self.db.scalar(select(MessageRevision).where(MessageRevision.message_id == message.id, MessageRevision.revision_fingerprint == fingerprint))
                    if revision is None:
                        latest = self.db.scalar(select(MessageRevision).where(MessageRevision.message_id == message.id).order_by(MessageRevision.revision_no.desc()))
                        revision = MessageRevision(message_id=message.id, revision_no=(latest.revision_no + 1 if latest else 1), role=item.role, content_text=item.content_text, content_json=item.content_json, model=item.model, raw_timestamp=item.raw_timestamp, content_hash=digest, revision_fingerprint=fingerprint, archive_object_id=archive_object_id, raw_json_pointer=f"/conversations/{parsed.external_id}/mapping/{item.node_id}"); self.db.add(revision); self.db.flush(); report["revisions"]["new"] += 1
                    else: report["revisions"]["existing"] += 1
                    resolved[item.node_id], revisions[item.node_id] = message, revision
                report["tree_anomalies"].extend(TreeValidator().validate(parsed.messages))
                for order, item in enumerate(parsed.messages):
                    if self.db.scalar(select(MessageObservation).where(MessageObservation.import_job_id == job.id, MessageObservation.external_node_id == item.node_id, MessageObservation.message_revision_id == revisions[item.node_id].id)): continue
                    parent = resolved.get(item.parent_node_id)
                    self.db.add(MessageObservation(import_job_id=job.id, message_id=resolved[item.node_id].id, message_revision_id=revisions[item.node_id].id, external_node_id=item.node_id, external_parent_node_id=item.parent_node_id, parent_message_id=parent.id if parent else None, branch_key=item.branch_key, is_current_path=item.node_id == parsed.current_node_id, observation_order=order, raw_mapping_pointer=f"/mapping/{item.node_id}", metadata_json={}))
                if lease_token is not None: ImportWorker(self.db).assert_ownership(job, lease_token)
                self.db.commit(); self.db.refresh(job)
            report["items"] = {"conversations": sum(report["conversations"].values()), "messages": sum(report["messages"].values())}
            job.report_json = report; job.items_discovered = report["items"]["messages"]; job.items_imported = report["messages"]["new"]; self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return job
