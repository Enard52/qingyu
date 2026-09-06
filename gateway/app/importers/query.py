from sqlalchemy import select
from ..models import Conversation, Message, MessageObservation

class ImportedTreeQuery:
    def __init__(self, db): self.db = db
    def get_children(self, message_id): return list(self.db.scalars(select(MessageObservation).where(MessageObservation.parent_message_id == message_id)))
    def get_roots(self, conversation_id): return list(self.db.scalars(select(MessageObservation).join(Message, Message.id == MessageObservation.message_id).where(Message.conversation_id == conversation_id, MessageObservation.parent_message_id.is_(None))))
    def get_leaves(self, conversation_id):
        rows=list(self.db.scalars(select(MessageObservation).join(Message, Message.id == MessageObservation.message_id).where(Message.conversation_id == conversation_id))); parents={r.parent_message_id for r in rows if r.parent_message_id}; return [r for r in rows if r.message_id not in parents]
    def get_path_to_leaf(self, leaf_message_id):
        rows={r.message_id:r for r in self.db.scalars(select(MessageObservation))}; out=[]; cur=leaf_message_id; seen=set()
        while cur in rows and cur not in seen: seen.add(cur); out.append(rows[cur]); cur=rows[cur].parent_message_id
        return list(reversed(out))

    def get_branch(self, conversation_id, branch_key):
        stmt = select(MessageObservation).join(Message).where(Message.conversation_id == conversation_id, MessageObservation.branch_key == branch_key).order_by(MessageObservation.observation_order)
        return list(self.db.scalars(stmt))

    def get_current_path(self, conversation_id):
        rows = list(self.db.scalars(select(MessageObservation).join(Message).where(Message.conversation_id == conversation_id, MessageObservation.is_current_path.is_(True)).order_by(MessageObservation.observation_order)))
        return rows
