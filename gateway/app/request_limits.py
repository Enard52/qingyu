from fastapi.responses import JSONResponse

from .config import get_settings


MULTIPART_OVERHEAD_BYTES = 1024 * 1024
UPLOAD_PATHS = frozenset({
    "/api/v1/import/chatgpt",
    "/api/v1/archive/objects",
})


class RequestBodyTooLarge(RuntimeError):
    pass


class ImportRequestSizeLimitMiddleware:
    """Bound upload request bodies before multipart parsing can spool them."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (
            scope.get("type") != "http"
            or scope.get("method") != "POST"
            or scope.get("path") not in UPLOAD_PATHS
        ):
            await self.app(scope, receive, send)
            return

        limit = get_settings().import_upload_max_bytes + MULTIPART_OVERHEAD_BYTES
        content_length = _content_length(scope)
        if content_length is not None and content_length > limit:
            await _send_too_large(scope, receive, send, limit)
            return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await _send_too_large(scope, receive, send, limit)


def _content_length(scope) -> int | None:
    for name, value in scope.get("headers", ()):
        if name.lower() == b"content-length":
            try:
                parsed = int(value)
            except (TypeError, ValueError):
                return None
            return parsed if parsed >= 0 else None
    return None


async def _send_too_large(scope, receive, send, limit: int) -> None:
    response = JSONResponse(
        status_code=413,
        content={"detail": f"请求体超过 {limit} 字节限制"},
    )
    await response(scope, receive, send)
