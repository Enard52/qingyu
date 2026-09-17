"""Explicit Scoped V2 HTTP composition using the existing pinned TLS socket.

The unsigned transport envelope carries exact canonical record bytes. It grants
no authority and adds no signed protocol field or remote semantic action. The
existing operation routes distinguish proposal/publication by their payload.
"""
from __future__ import annotations
import hmac
import http.client
import json
import math
import ssl
from urllib.parse import urlsplit
from uuid import UUID
from fastapi import Request

from .r1_client import _PinnedHTTPSConnection, AuthorityClient
from .r1_scoped_messages import AuthorityCaller, AuthorityReply
from ._r1_validation_stream import RegistrySlice
from .r1_validation_codec import ContractError, decode, require
from .r1_validation_crypto import FixedTrust

MAX_FRAME=16*1024*1024

class ScopedTransportUncertain(RuntimeError):pass
class ScopedHTTPRejected(RuntimeError):
    def __init__(self,status,code):
        self.status,self.code=status,code
        super().__init__(f'Authority HTTP {status}: {code}')

def _encode(value):
    raw=json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode('ascii')
    require(len(raw)<=MAX_FRAME,'transport frame limit')
    return raw

def _decode(raw):
    require(type(raw) is bytes and len(raw)<=MAX_FRAME,'transport frame limit')
    def pairs(items):
        out={}
        for k,v in items:
            require(k not in out,'duplicate transport field');out[k]=v
        return out
    try:value=json.loads(raw,object_pairs_hook=pairs)
    except (ValueError,RecursionError):raise ContractError('invalid transport JSON') from None
    require(_encode(value)==raw,'noncanonical transport envelope')
    return value

def registry_to_json(reg):
    require(type(reg) is RegistrySlice,'registry slice required')
    return {'header':reg.header_wire.hex(),'events':[w.hex() for w in reg.event_wires],
            'records':[[d,w.hex()] for d,w in reg.record_wires]}

def registry_from_json(value):
    require(type(value) is dict and set(value)=={'header','events','records'},'registry frame fields')
    try:
        reg=RegistrySlice(bytes.fromhex(value['header']),tuple(bytes.fromhex(w) for w in value['events']),
                          tuple((d,bytes.fromhex(w)) for d,w in value['records']))
    except (TypeError,ValueError):raise ContractError('invalid registry frame') from None
    require(len(reg.event_wires)<=4096 and len(reg.record_wires)<=16384,'registry delta bounds')
    for w in (reg.header_wire,*reg.event_wires,*(w for _,w in reg.record_wires)):decode(w)
    return reg

def reply_to_json(reply):
    return {name:getattr(reply,name).hex() if getattr(reply,name) is not None else None
            for name in ('request_wire','ack_wire','acceptance_wire','terminal_wire')} | {
                'state':reply.state,'authority':registry_to_json(reply.authority)}

def reply_from_json(value):
    require(type(value) is dict and set(value)=={'state','authority','request_wire','ack_wire','acceptance_wire','terminal_wire'},'reply fields')
    require(value['state'] in ('ABSENT','PREPARED','FIX_ACCEPTED','TERMINAL'),'reply phase')
    data={}
    for name in ('request_wire','ack_wire','acceptance_wire','terminal_wire'):
        try:data[name]=bytes.fromhex(value[name]) if value[name] is not None else None
        except (TypeError,ValueError):raise ContractError('reply original bytes') from None
        if data[name] is not None:decode(data[name])
    return AuthorityReply(state=value['state'],authority=registry_from_json(value['authority']),**data)

class ScopedAuthorityClient:
    _headers=AuthorityClient._headers
    def __init__(self,*,trust,ca_file,credential_provider,timeout_seconds=5):
        require(type(trust) is FixedTrust and trust.pin['api_version']==2,'explicit V2 fixed trust required')
        require(callable(credential_provider) and type(timeout_seconds) in (int,float)
                and math.isfinite(timeout_seconds) and timeout_seconds>0,'client configuration')
        self._pin=trust.pin;self._credential_provider=credential_provider;self._timeout=timeout_seconds
        origin=urlsplit(self._pin['https_origin']);self._host=origin.hostname;self._port=origin.port
        self._context=ssl.create_default_context(cafile=ca_file)
        self._context.minimum_version=ssl.TLSVersion.TLSv1_3
        self._context.set_alpn_protocols(['http/1.1'])
        self._closed=False

    def close(self):self._closed=True

    def _request(self,method,path,body=None):
        require(not self._closed,'client closed')
        conn=_PinnedHTTPSConnection(self._host,self._port,context=self._context,timeout=self._timeout,
                                   fingerprint=self._pin['server_spki_sha256'])
        try:
            conn.connect() # CA/hostname/TLS1.3/SPKI verified BEFORE credential acquisition.
            headers=self._headers()
            conn.request(method,path,body=_encode(body) if body is not None else None,headers=headers)
            response=conn.getresponse()
            raw=response.read(MAX_FRAME+1)
            if response.length not in (0,None):raise ScopedTransportUncertain('truncated response; query original ID')
            require(response.getheader('Content-Type','').split(';')[0]=='application/json','response media type')
            value=_decode(raw)
            if response.status!=200:
                code=value.get('error','HTTP_ERROR') if type(value) is dict else 'HTTP_ERROR'
                raise ScopedHTTPRejected(response.status,code)
            return reply_from_json(value)
        except (OSError,http.client.HTTPException):
            raise ScopedTransportUncertain('transport outcome unknown; query original ID') from None
        finally:conn.close()

    def prepare(self,request_wire,source_admission_wire,*,authority_after=0):
        return self._request('POST',f'/v1/operations?after={authority_after}',
            {'request':request_wire.hex(),'source_admission':source_admission_wire.hex()})

    def query(self,operation_id,request_wire,*,authority_after=0):
        require(str(UUID(operation_id))==operation_id,'canonical operation ID')
        # The original request digest is query context, never authentication.
        from .r1_validation_codec import h2
        return self._request('GET',f'/v1/operations/{operation_id}?after={authority_after}&request={h2(decode(request_wire))}')

    def decide(self,operation_id,request_wire,authorization_wire,proposal_wire,publication_wire,core_registry,*,authority_after=0):
        require(str(UUID(operation_id))==operation_id,'canonical operation ID')
        decision=decode(authorization_wire)['decision'].lower()
        require(decision in ('commit','abort'),'NORMAL decision required')
        return self._request('POST',f'/v1/operations/{operation_id}/{decision}?after={authority_after}',
            {'request':request_wire.hex(),'authorization':authorization_wire.hex(),'proposal':proposal_wire.hex(),
             'publication':publication_wire.hex() if publication_wire is not None else None,
             'core':registry_to_json(core_registry)})

class ScopedCredentialAuthenticator:
    """Protected credential lookup returns an actual registered subject."""
    def __init__(self,lookup):
        require(callable(lookup),'protected credential lookup required');self.lookup=lookup
    def __call__(self,token):
        caller=self.lookup(token)
        require(type(caller) is AuthorityCaller,'authenticated registered caller required')
        return caller

def create_scoped_authority_app(coordinator,authenticator,*,response_hook=None):
    from fastapi import FastAPI,Request
    from fastapi.responses import Response
    from .r1_scoped_authority import ScopedAuthority
    require(type(coordinator) is ScopedAuthority and callable(authenticator),'explicit scoped composition')
    app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
    def answer(value,status=200):return Response(_encode(value),status_code=status,media_type='application/json',headers={'Cache-Control':'private, no-store'})
    def caller_for(request):
        require(request.scope.get('scheme')=='https','direct authenticated TLS required')
        values=request.headers.getlist('authorization')
        require(len(values)==1 and values[0].startswith('Bearer '),'one Bearer credential required')
        token=values[0][7:]
        require(token and all(33<=ord(c)<=126 for c in token),'invalid credential encoding')
        return authenticator(token)
    async def body_for(request):
        require(request.headers.get('content-type','').split(';')[0]=='application/json','JSON body required')
        raw=bytearray()
        async for chunk in request.stream():
            raw.extend(chunk);require(len(raw)<=MAX_FRAME,'transport body limit')
        return _decode(bytes(raw))
    def after_for(request):
        text=request.query_params.get('after','0')
        require(text.isascii() and text.isdecimal() and len(text)<16,'history cursor')
        return int(text)
    async def dispatch(request,operation_id=None,decision=None):
        try:
            caller=caller_for(request);after=after_for(request)
            if operation_id is not None:require(str(UUID(operation_id))==operation_id,'canonical operation ID')
            if request.method=='GET':
                # Product query binds original digest without trusting request body identity.
                digest=request.query_params.get('request','')
                reply=coordinator.query(operation_id,None,caller,authority_after=after,request_digest=digest)
            else:
                body=await body_for(request)
                if operation_id is None:
                    require(set(body)=={'request','source_admission'},'prepare frame fields')
                    reply=coordinator.prepare(bytes.fromhex(body['request']),bytes.fromhex(body['source_admission']),caller,authority_after=after)
                else:
                    require(set(body)=={'request','authorization','proposal','publication','core'},'decision frame fields')
                    authorization=bytes.fromhex(body['authorization'])
                    require(decode(authorization)['decision'].lower()==decision,'route decision mismatch')
                    reply=coordinator.decide(operation_id,bytes.fromhex(body['request']),authorization,bytes.fromhex(body['proposal']),
                        bytes.fromhex(body['publication']) if body['publication'] is not None else None,
                        registry_from_json(body['core']),caller,authority_after=after)
            if response_hook:response_hook(reply)
            return answer(reply_to_json(reply))
        except ContractError:return answer({'error':'CONTRACT_REJECTED'},409)
        except (ValueError,KeyError,TypeError):return answer({'error':'INVALID_REQUEST'},400)
        except Exception as exc:
            from .r1_postgres_store import StoreError
            if isinstance(exc,StoreError):return answer({'error':exc.code},503 if exc.code=='DATABASE_UNAVAILABLE' else 409)
            raise
    @app.post('/v1/operations')
    async def prepare(request:Request):return await dispatch(request)
    @app.get('/v1/operations/{operation_id}')
    async def query(operation_id:str,request:Request):return await dispatch(request,operation_id)
    @app.post('/v1/operations/{operation_id}/commit')
    async def commit(operation_id:str,request:Request):return await dispatch(request,operation_id,'commit')
    @app.post('/v1/operations/{operation_id}/abort')
    async def abort(operation_id:str,request:Request):return await dispatch(request,operation_id,'abort')
    return app
