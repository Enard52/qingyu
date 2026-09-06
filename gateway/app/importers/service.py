import hashlib
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session
from .generic import GenericTreeParser
from ..models import SourceAccount, ImportJob, Conversation, Message, MessageRevision, MessageObservation, Attachment
from .worker import ImportWorker, LeaseLost

class ImportService:
    def __init__(self, db: Session):
        self.db = db

    def import_fixture(self, payload: dict[str, Any], archive_object_id, platform: str = "fixture", account_label: str = "default", job: ImportJob | None = None, lease_token=None) -> ImportJob:
        account = self.db.scalar(select(SourceAccount).where(SourceAccount.platform == platform, SourceAccount.account_label == account_label))
        if account is None:
            account = SourceAccount(platform=platform, account_label=account_label, metadata_json={})
            self.db.add(account)
            self.db.flush()
        if job is None:
            job = ImportJob(source_account_id=account.id, archive_object_id=archive_object_id, parser_name=GenericTreeParser.name, parser_version=GenericTreeParser.version, status="running", report_json={})
            self.db.add(job); self.db.flush()
            lease_token = job.lease_token
        report = {"unknown_fields": [], "orphan_nodes": [], "imported_conversations": 0, "imported_messages": 0}
        try:
            for parsed in GenericTreeParser().parse(payload):
                if lease_token is not None: ImportWorker(self.db).assert_ownership(job, lease_token)
                conversation = self.db.scalar(select(Conversation).where(Conversation.source_account_id == account.id, Conversation.external_conversation_id == parsed.external_id)) if parsed.external_id else None
                if conversation is None:
                    conversation = Conversation(source_account_id=account.id, external_conversation_id=parsed.external_id, title=parsed.title, metadata_json={})
                    self.db.add(conversation)
                    self.db.flush()
                report["imported_conversations"] += 1
                node_map = {}
                for order, item in enumerate(parsed.messages):
                    message = self.db.scalar(select(Message).where(Message.conversation_id == conversation.id, Message.external_message_id == item.node_id))
                    if message is None:
                        message = Message(conversation_id=conversation.id, external_message_id=item.node_id)
                        self.db.add(message)
                        self.db.flush()
                    revision = self.db.scalar(select(MessageRevision).where(MessageRevision.message_id == message.id, MessageRevision.revision_no == 1))
                    if revision is None:
                        revision = MessageRevision(message_id=message.id, revision_no=1, role=item.role, content_text=item.content_text, content_json=item.content_json, model=item.model, raw_timestamp=item.raw_timestamp, content_hash=hashlib.sha256((item.content_text or "").encode()).hexdigest(), archive_object_id=archive_object_id, raw_json_pointer=f"/conversations/{parsed.external_id}/mapping/{item.node_id}")
                        self.db.add(revision)
                        self.db.flush()
                    parent = node_map.get(item.parent_node_id)
                    self.db.add(MessageObservation(import_job_id=job.id, message_id=message.id, message_revision_id=revision.id, external_node_id=item.node_id, external_parent_node_id=item.parent_node_id, parent_message_id=parent, branch_key=item.branch_key, is_current_path=item.node_id == parsed.current_node_id, observation_order=order, raw_mapping_pointer=f"/mapping/{item.node_id}", metadata_json={}))
                    node_map[item.node_id] = message.id
                    report["imported_messages"] += 1
                    if isinstance(item.content_json, dict):
                        for att in item.content_json.get("attachments", []):
                            self.db.add(Attachment(message_revision_id=revision.id, external_attachment_id=str(att.get("id")) if isinstance(att, dict) and att.get("id") else None, original_reference=str(att), filename=att.get("filename") if isinstance(att, dict) else None, availability_status="referenced_only", metadata_json={}))
            job.items_discovered = report["imported_messages"]
            job.items_imported = report["imported_messages"]
            job.status = "completed"
            job.report_json = report
            if lease_token is not None: ImportWorker(self.db).assert_ownership(job, lease_token)
            self.db.commit()
        except Exception as exc:
            self.db.rollback()
            job.status = "failed"
            job.error_summary = str(exc)
            self.db.add(job)
            self.db.commit()
            raise
        return job
