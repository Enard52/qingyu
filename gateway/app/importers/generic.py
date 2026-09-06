from dataclasses import dataclass
from typing import Any, Iterator


class ParserValidationError(ValueError):
    def __init__(self, errors):
        self.errors = errors
        super().__init__("parser_validation_error")


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
    marker = "qingyu-fixture-v1"
    top_fields = {"schema_marker", "conversations"}
    conversation_fields = {"id", "title", "current_node", "mapping", "metadata"}
    node_fields = {"id", "parent", "children", "message", "metadata"}
    message_fields = {
        "id", "author", "content", "metadata", "model", "create_time",
        "update_time", "attachments",
    }
    author_fields = {"role", "name", "metadata"}
    content_fields = {"content_type", "parts", "text", "metadata"}

    def can_parse(self, payload) -> bool:
        return isinstance(payload, dict) and payload.get("schema_marker") == self.marker and isinstance(payload.get("conversations"), list)

    def validate(self, payload: Any, member="fixture.json") -> list[dict]:
        errors = []
        unknown = []
        if not isinstance(payload, dict):
            raise ParserValidationError([{"type": "invalid_top_level", "raw_pointer": "", "detail": "expected JSON object"}])
        if payload.get("schema_marker") != self.marker:
            errors.append({"type": "invalid_schema_marker", "raw_pointer": "/schema_marker", "detail": "unsupported fixture marker"})
        conversations = payload.get("conversations")
        if not isinstance(conversations, list):
            errors.append({"type": "invalid_conversations", "raw_pointer": "/conversations", "detail": "expected array"})
            conversations = []
        self._unknown_fields(payload, self.top_fields, "", member, unknown)
        for index, conversation in enumerate(conversations):
            base = f"/conversations/{index}"
            if not isinstance(conversation, dict):
                self._error(errors, "invalid_conversation", base, "expected object")
                continue
            self._unknown_fields(conversation, self.conversation_fields, base, member, unknown)
            self._optional_type(conversation, "id", str, errors, base)
            self._optional_type(conversation, "title", str, errors, base)
            self._optional_type(conversation, "current_node", str, errors, base)
            self._optional_mapping(conversation, "metadata", errors, base)
            mapping = conversation.get("mapping")
            if not isinstance(mapping, dict):
                self._error(errors, "invalid_mapping", f"{base}/mapping", "expected object")
                continue
            for node_id, node in mapping.items():
                pointer = f"{base}/mapping/{pointer_escape(node_id)}"
                if not isinstance(node, dict):
                    self._error(errors, "invalid_node", pointer, "expected object")
                    continue
                self._unknown_fields(node, self.node_fields, pointer, member, unknown)
                self._optional_type(node, "id", str, errors, pointer)
                self._optional_type(node, "parent", str, errors, pointer)
                self._optional_mapping(node, "metadata", errors, pointer)
                self._string_list(node, "children", errors, pointer)
                message = node.get("message")
                if not isinstance(message, dict):
                    self._error(errors, "invalid_message", f"{pointer}/message", "expected object")
                    continue
                self._validate_message(message, pointer, member, errors, unknown)
        if errors:
            raise ParserValidationError(errors)
        return unknown

    def _validate_message(self, message, node_pointer, member, errors, unknown):
        base = f"{node_pointer}/message"
        self._unknown_fields(message, self.message_fields, base, member, unknown)
        self._optional_type(message, "id", str, errors, base)
        self._optional_type(message, "model", str, errors, base)
        self._optional_scalar(message, "create_time", errors, base)
        self._optional_scalar(message, "update_time", errors, base)
        self._optional_mapping(message, "metadata", errors, base)
        self._list_field(message, "attachments", errors, base)

        author = message.get("author")
        if not isinstance(author, dict):
            self._error(errors, "invalid_author", f"{base}/author", "expected object")
        else:
            self._unknown_fields(author, self.author_fields, f"{base}/author", member, unknown)
            self._optional_type(author, "role", str, errors, f"{base}/author")
            self._optional_type(author, "name", str, errors, f"{base}/author")
            self._optional_mapping(author, "metadata", errors, f"{base}/author")

        content = message.get("content")
        if not isinstance(content, dict):
            self._error(errors, "invalid_content", f"{base}/content", "expected object")
        else:
            self._unknown_fields(content, self.content_fields, f"{base}/content", member, unknown)
            self._optional_type(content, "content_type", str, errors, f"{base}/content")
            self._optional_type(content, "text", str, errors, f"{base}/content")
            self._optional_mapping(content, "metadata", errors, f"{base}/content")
            self._list_field(content, "parts", errors, f"{base}/content")

        metadata = message.get("metadata")
        if isinstance(metadata, dict):
            self._optional_type(metadata, "model_slug", str, errors, f"{base}/metadata")

    @staticmethod
    def _error(errors, error_type, pointer, detail):
        errors.append({"type": error_type, "raw_pointer": pointer, "detail": detail})

    def _optional_type(self, value, field, expected, errors, base):
        if field in value and value[field] is not None and not isinstance(value[field], expected):
            self._error(errors, f"invalid_{field}", f"{base}/{pointer_escape(field)}", f"expected {expected.__name__} or null")

    def _optional_mapping(self, value, field, errors, base):
        if field in value and value[field] is not None and not isinstance(value[field], dict):
            self._error(errors, f"invalid_{field}", f"{base}/{pointer_escape(field)}", "expected object or null")

    def _list_field(self, value, field, errors, base):
        if field in value and value[field] is not None and not isinstance(value[field], list):
            self._error(errors, f"invalid_{field}", f"{base}/{pointer_escape(field)}", "expected array or null")

    def _string_list(self, value, field, errors, base):
        self._list_field(value, field, errors, base)
        if isinstance(value.get(field), list) and any(not isinstance(item, str) for item in value[field]):
            self._error(errors, f"invalid_{field}", f"{base}/{pointer_escape(field)}", "expected array of strings")

    def _optional_scalar(self, value, field, errors, base):
        item = value.get(field)
        if field in value and item is not None and (isinstance(item, bool) or not isinstance(item, (str, int, float))):
            self._error(errors, f"invalid_{field}", f"{base}/{pointer_escape(field)}", "expected string, number, or null")

    @staticmethod
    def _unknown_fields(value, allowed, base, member, unknown):
        for field in value.keys() - allowed:
            unknown.append({"type": "unknown_field", "severity": "warning", "file": member, "field": field, "raw_pointer": f"{base}/{pointer_escape(field)}"})

    def parse(self, payload: dict[str, Any]) -> Iterator[ParsedConversation]:
        self.validate(payload)
        for conversation in payload["conversations"]:
            nodes=[]
            for node_id,node in conversation["mapping"].items():
                message=node["message"]; author=message.get("author") or {}; content=message.get("content") or {}; parts=content.get("parts")
                text="\n".join(str(part) for part in parts) if isinstance(parts,list) else (str(content) if content else None)
                nodes.append(ParsedMessage(str(node_id),node.get("parent"),str(author.get("role","unknown")),text,content,(message.get("metadata") or {}).get("model_slug"),str(message.get("create_time")) if message.get("create_time") is not None else None,None))
            yield ParsedConversation(conversation.get("id"),conversation.get("title"),tuple(nodes),conversation.get("current_node"))


class ParserRegistry:
    def __init__(self, parsers=None): self.parsers=list(parsers or [GenericTreeParser()])
    def detect(self, payload) -> tuple[str, Any]:
        if not isinstance(payload,dict): return "unsupported_structure",None
        matches=[parser for parser in self.parsers if parser.can_parse(payload)]
        if len(matches)>1: return "ambiguous_structure",None
        if not matches: return ("unsupported_real_chatgpt_export" if "conversations" in payload else "unsupported_structure"),None
        return "matched",matches[0]


def pointer_escape(value) -> str: return str(value).replace("~","~0").replace("/","~1")
