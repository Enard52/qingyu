"""HTTPS boundary for durable ordinary authorization.

Runtime credentials select only an initialized principal.  Operation routes
derive their policy/session/inventory/grant caller from the locked Authority
registry after the operation identifier has been parsed.  Operator routes use
a distinct authenticator fixed by service composition.
"""
from __future__ import annotations

from uuid import UUID

from fastapi import Request
from fastapi.responses import Response

from .r1_validation_codec import ContractError, decode, h2, require
from .r1_scoped_transport import (
    MAX_FRAME, ScopedAuthorityClient, _decode, _encode, registry_from_json,
    reply_to_json,
)


class DurableCredential:
    """Fixed runtime credential used only after pinned TLS succeeds."""
    def __init__(self, token: str):
        require(type(token) is str and token and all(33 <= ord(c) <= 126 for c in token),
                "durable credential encoding")
        self._token = token

    def __call__(self):
        return self._token

    def for_request(self, method, path, body):
        return self._token


class DurableAuthorityClient(ScopedAuthorityClient):
    def ensure_execution(self, request_wire, source_wire, *, authority_after=0):
        return self._request('POST', f'/v1/authorization/grants?after={authority_after}',
            {'request': request_wire.hex(), 'source_admission': source_wire.hex()})

    def ensure_permit(self, operation_id, request_wire, *, authority_after=0):
        require(str(UUID(operation_id)) == operation_id, 'canonical operation ID')
        return self._request('POST',
            f'/v1/authorization/permits/{operation_id}?after={authority_after}',
            {'request_digest': h2(decode(request_wire))})


def create_durable_authority_app(authority, provider, *, operator_authenticator,
                                 response_hook=None):
    """Compose product Authority and provider without a Root key online."""
    from fastapi import FastAPI
    from .r1_scoped_authority import ScopedAuthority
    from .r1_durable_authorization import DurableAuthorizationProvider

    require(type(authority) is ScopedAuthority and
            type(provider) is DurableAuthorizationProvider and
            provider.authority is authority and callable(operator_authenticator),
            'explicit durable Authority composition')
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def answer(value, status=200):
        return Response(_encode(value), status_code=status, media_type='application/json',
                        headers={'Cache-Control': 'private, no-store'})

    def bearer(request):
        require(request.scope.get('scheme') == 'https', 'direct authenticated TLS required')
        values = request.headers.getlist('authorization')
        require(len(values) == 1 and values[0].startswith('Bearer '),
                'one Bearer credential required')
        token = values[0][7:]
        require(token and all(33 <= ord(c) <= 126 for c in token),
                'invalid credential encoding')
        return token

    async def body_for(request):
        require(request.headers.get('content-type', '').split(';')[0] == 'application/json',
                'JSON body required')
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            require(len(raw) <= MAX_FRAME, 'transport body limit')
        return _decode(bytes(raw))

    def after_for(request):
        text = request.query_params.get('after', '0')
        require(text.isascii() and text.isdecimal() and len(text) < 16, 'history cursor')
        return int(text)

    async def runtime_dispatch(request, operation_id=None, decision=None, qualification=None):
        try:
            token = bearer(request).encode('ascii')
            after = after_for(request)
            body = None if request.method == 'GET' else await body_for(request)
            if qualification == 'grant':
                require(set(body) == {'request', 'source_admission'}, 'grant frame fields')
                request_wire = bytes.fromhex(body['request'])
                source_wire = bytes.fromhex(body['source_admission'])
                op = decode(request_wire)['intent']['operation_id']
                principal = provider.authenticate_principal(token)
                issued = provider.ensure_execution(request_wire, source_wire,
                                                   runtime_principal=principal)
                require(issued.caller.runtime_principal == principal, 'issued principal differs')
                reply = authority.query(op, request_wire, issued.caller,
                                        authority_after=after)
            elif qualification == 'permit':
                require(str(UUID(operation_id)) == operation_id and
                        set(body) == {'request_digest'}, 'permit frame')
                principal = provider.authenticate_principal(token)
                issued = provider.ensure_permit(operation_id, runtime_principal=principal,
                                                request_digest=body['request_digest'])
                reply = authority.query(operation_id, None, issued.caller, authority_after=after,
                                        request_digest=body['request_digest'])
            elif request.method == 'GET':
                require(str(UUID(operation_id)) == operation_id, 'canonical operation ID')
                caller = provider.authenticate(token, operation_id, allow_terminal_query=True)
                reply = authority.query(operation_id, None, caller, authority_after=after,
                    request_digest=request.query_params.get('request', ''))
            elif operation_id is None:
                require(set(body) == {'request', 'source_admission'}, 'prepare frame fields')
                request_wire = bytes.fromhex(body['request'])
                op = decode(request_wire)['intent']['operation_id']
                caller = provider.authenticate(token, op)
                reply = authority.prepare(request_wire, bytes.fromhex(body['source_admission']),
                                          caller, authority_after=after)
            else:
                require(str(UUID(operation_id)) == operation_id and
                        set(body) == {'request', 'authorization', 'proposal', 'publication', 'core'},
                        'decision frame fields')
                caller = provider.authenticate(token, operation_id)
                authorization = bytes.fromhex(body['authorization'])
                require(decode(authorization)['decision'].lower() == decision,
                        'route decision mismatch')
                reply = authority.decide(operation_id, bytes.fromhex(body['request']),
                    authorization, bytes.fromhex(body['proposal']),
                    bytes.fromhex(body['publication']) if body['publication'] is not None else None,
                    registry_from_json(body['core']), caller, authority_after=after)
            if response_hook:
                response_hook(reply)
            return answer(reply_to_json(reply))
        except ContractError:
            return answer({'error': 'CONTRACT_REJECTED'}, 409)
        except (ValueError, KeyError, TypeError):
            return answer({'error': 'INVALID_REQUEST'}, 400)
        except Exception as exc:
            from .r1_postgres_store import StoreError
            if isinstance(exc, StoreError):
                return answer({'error': exc.code},
                              503 if exc.code == 'DATABASE_UNAVAILABLE' else 409)
            raise

    @app.post('/v1/authorization/grants')
    async def grant(request: Request):
        return await runtime_dispatch(request, qualification='grant')

    @app.post('/v1/authorization/permits/{operation_id}')
    async def permit(operation_id: str, request: Request):
        return await runtime_dispatch(request, operation_id, qualification='permit')

    @app.post('/v1/operations')
    async def prepare(request: Request):
        return await runtime_dispatch(request)

    @app.get('/v1/operations/{operation_id}')
    async def query(operation_id: str, request: Request):
        return await runtime_dispatch(request, operation_id)

    @app.post('/v1/operations/{operation_id}/commit')
    async def commit(operation_id: str, request: Request):
        return await runtime_dispatch(request, operation_id, 'commit')

    @app.post('/v1/operations/{operation_id}/abort')
    async def abort(operation_id: str, request: Request):
        return await runtime_dispatch(request, operation_id, 'abort')

    @app.post('/v1/operator/revocations')
    async def revoke(request: Request):
        try:
            token = bearer(request)
            require(operator_authenticator(token) is True, 'operator credential rejected')
            body = await body_for(request)
            require(set(body) == {'kind', 'object_digest', 'authorization'},
                    'revocation frame fields')
            authorization = bytes.fromhex(body['authorization'])
            sequence = provider.revoke(body['kind'], body['object_digest'], authorization,
                verify_operator=lambda wire, kind, digest, now:
                    operator_authenticator(token, wire, kind, digest, now) is True)
            return answer({'authority_sequence': sequence})
        except ContractError:
            return answer({'error': 'CONTRACT_REJECTED'}, 409)
        except (ValueError, KeyError, TypeError):
            return answer({'error': 'INVALID_REQUEST'}, 400)

    return app
