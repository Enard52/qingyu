from dataclasses import dataclass
from typing import Any, Iterator

@dataclass(frozen=True)
class ParsedMessage:
    node_id: str
    parent_node_id: str | None
    role: str
    content_text: str | None
    content_json: Any
    model: str | None
    raw_timestamp: str | None
    branch_key: str | None

@dataclass(frozen=True)
class ParsedConversation:
    external_id: str | None
    title: str | None
    messages: tuple[ParsedMessage, ...]
    current_node_id: str | None

class GenericTreeParser:
    """Parser for the project fixture contract; not a claim of ChatGPT compatibility."""
    name = "generic-tree-fixture"
    version = "0.1"

    def parse(self, payload: dict[str, Any]) -> Iterator[ParsedConversation]:
        for conversation in payload.get("conversations", []):
            mapping = conversation.get("mapping") or {}
            nodes = []
            for node_id, node in mapping.items():
                message = node.get("message") or {}
                author = message.get("author") or {}
                content = message.get("content") or {}
                parts = content.get("parts") if isinstance(content, dict) else None
                text = "\n".join(str(p) for p in parts) if isinstance(parts, list) else (str(content) if content else None)
                nodes.append(ParsedMessage(str(node_id), node.get("parent"), str(author.get("role", "unknown")), text, content, message.get("metadata", {}).get("model_slug"), str(message.get("create_time")) if message.get("create_time") is not None else None, None))
            yield ParsedConversation(conversation.get("id"), conversation.get("title"), tuple(nodes), conversation.get("current_node"))
