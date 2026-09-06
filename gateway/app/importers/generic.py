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
    conversation_fields = {"id", "title", "current_node", "mapping"}

    def can_parse(self, payload) -> bool:
        return isinstance(payload, dict) and payload.get("schema_marker") == self.marker and isinstance(payload.get("conversations"), list)

    def validate(self, payload: Any, member="fixture.json") -> list[dict]:
        errors=[]; unknown=[]
        if not isinstance(payload, dict): raise ParserValidationError([{"type":"invalid_top_level","raw_pointer":"","detail":"expected JSON object"}])
        if payload.get("schema_marker") != self.marker: errors.append({"type":"invalid_schema_marker","raw_pointer":"/schema_marker","detail":"unsupported fixture marker"})
        conversations=payload.get("conversations")
        if not isinstance(conversations, list): errors.append({"type":"invalid_conversations","raw_pointer":"/conversations","detail":"expected array"}); conversations=[]
        for field in payload.keys()-self.top_fields: unknown.append({"type":"unknown_field","severity":"warning","file":member,"field":field,"raw_pointer":f"/{pointer_escape(field)}"})
        for index, conversation in enumerate(conversations):
            base=f"/conversations/{index}"
            if not isinstance(conversation, dict): errors.append({"type":"invalid_conversation","raw_pointer":base,"detail":"expected object"}); continue
            for field in conversation.keys()-self.conversation_fields: unknown.append({"type":"unknown_field","severity":"warning","file":member,"field":field,"raw_pointer":f"{base}/{pointer_escape(field)}"})
            mapping=conversation.get("mapping")
            if not isinstance(mapping, dict): errors.append({"type":"invalid_mapping","raw_pointer":f"{base}/mapping","detail":"expected object"}); continue
            for node_id,node in mapping.items():
                pointer=f"{base}/mapping/{pointer_escape(node_id)}"
                if not isinstance(node,dict): errors.append({"type":"invalid_node","raw_pointer":pointer,"detail":"expected object"}); continue
                if node.get("parent") is not None and not isinstance(node.get("parent"),str): errors.append({"type":"invalid_parent","raw_pointer":f"{pointer}/parent","detail":"expected string or null"})
                message=node.get("message")
                if not isinstance(message,dict): errors.append({"type":"invalid_message","raw_pointer":f"{pointer}/message","detail":"expected object"}); continue
                if not isinstance(message.get("author",{}),dict): errors.append({"type":"invalid_author","raw_pointer":f"{pointer}/message/author","detail":"expected object"})
                content=message.get("content",{})
                if not isinstance(content,dict): errors.append({"type":"invalid_content","raw_pointer":f"{pointer}/message/content","detail":"expected object"})
                elif "parts" in content and not isinstance(content["parts"],list): errors.append({"type":"invalid_parts","raw_pointer":f"{pointer}/message/content/parts","detail":"expected array"})
        if errors: raise ParserValidationError(errors)
        return unknown

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
