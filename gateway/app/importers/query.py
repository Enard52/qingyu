from sqlalchemy import select
from ..models import Message, MessageObservation


class ImportedTreeQuery:
    def __init__(self, db): self.db = db

    def _snapshot(self, conversation_id, import_job_id):
        statement = select(MessageObservation).join(Message, Message.id == MessageObservation.message_id).where(Message.conversation_id == conversation_id, MessageObservation.import_job_id == import_job_id).order_by(MessageObservation.observation_order)
        return list(self.db.scalars(statement))

    def get_tree(self, conversation_id, import_job_id): return self._snapshot(conversation_id, import_job_id)

    def get_roots(self, conversation_id, import_job_id):
        return [row for row in self._snapshot(conversation_id, import_job_id) if row.parent_message_id is None]

    def get_children(self, conversation_id, import_job_id, message_id):
        return [row for row in self._snapshot(conversation_id, import_job_id) if row.parent_message_id == message_id]

    def get_leaves(self, conversation_id, import_job_id):
        rows = self._snapshot(conversation_id, import_job_id); parents = {row.parent_message_id for row in rows if row.parent_message_id}
        return [row for row in rows if row.message_id not in parents]

    def get_path_to_leaf(self, conversation_id, import_job_id, leaf_message_id):
        rows = {row.message_id: row for row in self._snapshot(conversation_id, import_job_id)}; path=[]; current=leaf_message_id; seen=set()
        while current in rows and current not in seen:
            seen.add(current); path.append(rows[current]); current=rows[current].parent_message_id
        return list(reversed(path))

    def get_branch(self, conversation_id, import_job_id, leaf_message_id):
        return self.get_path_to_leaf(conversation_id, import_job_id, leaf_message_id)

    def get_current_path(self, conversation_id, import_job_id):
        current = next((row for row in self._snapshot(conversation_id, import_job_id) if row.is_current_path), None)
        return [] if current is None else self.get_path_to_leaf(conversation_id, import_job_id, current.message_id)
