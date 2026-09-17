"""Controlled intake/governance issuer for real Slice03 integration.

Only initial trust, source admission, qualifications and finish permits are
provided. Ack, FIX, terminal and completion are never manufactured here.
"""
from pathlib import Path
from copy import deepcopy
from uuid import uuid4,uuid5,NAMESPACE_URL
import datetime,hashlib,ipaddress,json,secrets,socket,time
from dataclasses import asdict
from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import ec,ed25519
from cryptography.x509.oid import NameOID
from app.control_plane.r1_validation_codec import ACTIONS,SCHEMA,c2,decode,h2,obj,record,s2,sha
from app.control_plane.r1_validation_crypto import FixedTrust
from app.control_plane._r1_validation_semantics import DeploymentEvidence,header
from app.control_plane._r1_validation_stream import RegistrySlice,WindowEvidence,registry_slice
from app.control_plane.r1_validation import ChainBoundary
from app.control_plane.r1_scoped_messages import AuthorityCaller

def now_ms():return time.time_ns()//1_000_000
def uid():return str(uuid4())
def stable(op,name):return str(uuid5(NAMESPACE_URL,op+'/'+name))
def raw(value):return sha(c2(value))
def public(key):return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
def registry(pin,material=None):return {'header':header(pin,material),'events':[],'records':{}}
def pos(reg):return {'history_version':2,'registry_digest':raw(reg['header']),'event_sequence':len(reg['events'])+1}
def put(reg,value):
    digest=h2(value) if value.get('type') in SCHEMA else raw(value)
    reg['records'][digest]=deepcopy(value);return digest
def event(reg,kind,at,inp,out=None):
    reg['records'][raw(inp)]=deepcopy(inp);put(reg,inp)
    ev=record('registry_event',history_version=2,position=pos(reg),recorded_at=at,event_kind=kind,input_digest=raw(inp),output_digest=put(reg,out) if out else None)
    reg['events'].append(ev);return ev
def merge(left,right):
    if isinstance(right,RegistrySlice):right={'header':decode(right.header_wire),'events':[decode(w) for w in right.event_wires],'records':{d:decode(w) for d,w in right.record_wires}}
    if left is None:return deepcopy(right)
    assert left['header']==right['header']
    out=deepcopy(left)
    for ev in right['events']:
        n=ev['position']['event_sequence']
        if n<=len(out['events']):assert out['events'][n-1]==ev
        else:assert n==len(out['events'])+1;out['events'].append(deepcopy(ev))
    for d,v in right['records'].items():
        assert d not in out['records'] or out['records'][d]==v
        out['records'][d]=deepcopy(v)
    return out

def delta(reg,prior):
    if prior is None:return registry_slice(reg)
    if isinstance(prior,bytes):prior=registry_slice(decode(prior))
    events=prior.event_wires;records=dict(prior.record_wires)
    assert c2(reg['header'])==prior.header_wire
    assert all(c2(reg['events'][decode(w)['position']['event_sequence']-1])==w for w in events)
    last=max((decode(w)['position']['event_sequence'] for w in events),default=0)
    return RegistrySlice(prior.header_wire,tuple(c2(e) for e in reg['events'][last:]),tuple((d,c2(v)) for d,v in reg['records'].items() if d not in records))

def bootstrap(config_path):
    path=Path(config_path);config=json.loads(path.read_text());folder=path.parent
    if 'pin' in config:return config
    receipt=ed25519.Ed25519PrivateKey.generate();root=ed25519.Ed25519PrivateKey.generate()
    ca_key=ec.generate_private_key(ec.SECP256R1());tls_key=ec.generate_private_key(ec.SECP256R1())
    now=datetime.datetime.now(datetime.timezone.utc)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Qingyu Slice03 temporary CA')])
    ca=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(ca_key,hashes.SHA256())
    leaf=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])).issuer_name(name).public_key(tls_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False).sign(ca_key,hashes.SHA256())
    for fn,key in (('receipt.key',receipt),('root.key',root),('tls.key',tls_key)):
        (folder/fn).write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (folder/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM));(folder/'tls.pem').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    der=tls_key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    pin=obj('authority_pin',authority_domain_id=uid(),authority_instance_id=uid(),authority_generation=1,receipt_public_key=public(receipt).hex(),receipt_key_id=sha(public(receipt)),api_version=2,https_origin=f'https://127.0.0.1:{port}',server_spki_sha256=sha(der),operator_root_key_id=sha(public(root)))
    identity=obj('identity',qingyu_identity_id=uid(),continuity_id=uid(),genesis_operation_id=uid())
    checkpoint=obj('local_checkpoint',state_version=4,authority_ref=obj('authority_ref',wire_version=2,authority_generation=1,authority_sequence=4,receipt_hash='a'*64),audit_ref=obj('audit_ref',wire_version=2,audit_sequence=4,audit_hash='b'*64))
    config.update(pin=pin,identity=identity,checkpoint=checkpoint,scope_id=uid(),core_installation_id=uid(),storage_generation_id=uid(),control_plane_generation_id=uid(),trust_domain_id=uid(),runtime_principal='slice03-test-core',actor_identity='slice03-original-caller',tls_der=der.hex(),root_public=public(root).hex(),authority_port=port,credential=secrets.token_urlsafe(32))
    path.write_text(json.dumps(config),encoding='utf8');return config

def material(config):return DeploymentEvidence(config['runtime_principal'],config['core_installation_id'],config['storage_generation_id'],config['control_plane_generation_id'],b'slice03-controlled-deployment',b'slice03-controlled-component',bytes.fromhex(config['tls_der']))
def trust(config):return FixedTrust(c2(config['pin']),bytes.fromhex(config['root_public']))
def boundary(config):return ChainBoundary(c2(config['identity']),c2(config['checkpoint']),c2(config['checkpoint']),config['actor_identity'],1,1,config['storage_generation_id'],config['control_plane_generation_id'],config['trust_domain_id'])
def scope_wire(config):return c2({'identity':config['identity'],'core_installation_id':config['core_installation_id'],'storage_generation_id':config['storage_generation_id'],'control_plane_generation_id':config['control_plane_generation_id'],'trust_domain_id':config['trust_domain_id'],'owner_identity':config['actor_identity'],'owner_version':1,'continuity_epoch':1})

class ControlledProvider:
    def __init__(self,config_path,authority=None):
        self.path=Path(config_path);self.config=json.loads(self.path.read_text());self.folder=self.path.parent
        self.authority_service=authority
        self.deployment=material(self.config);self.pin=self.config['pin']
        self.root=serialization.load_pem_private_key((self.folder/'root.key').read_bytes(),None)
        self.receipt=serialization.load_pem_private_key((self.folder/'receipt.key').read_bytes(),None)
        self.a=registry(self.pin);self.core=registry(self.pin,self.deployment);self.requests={}
    def now_ms(self):return now_ms()
    def sign(self,value):
        field='root_signature' if 'root_signature' in value else 'receipt_signature'
        value[field]=(self.root if field=='root_signature' else self.receipt).sign(s2(value)).hex();return value
    def admit_original(self,request_wire,source_wire):
        request=decode(request_wire);admission=decode(source_wire);op=request['intent']['operation_id']
        owned=self.folder/('intake-'+op+'.json')
        assert owned.is_file(),'intake was not independently admitted'
        saved=json.loads(owned.read_text());assert saved=={'request':request_wire.hex(),'source':source_wire.hex()}
        assert request['intent']['scope']['actor_identity']==self.config['actor_identity']
        self.requests[op]=(request_wire,source_wire);return source_wire
    def intake(self,request_wire):
        request=decode(request_wire);intent=request['intent'];s=intent['scope'];at=intent['created_at'];d=self.deployment
        admission=record('source_admission',operation_id=intent['operation_id'],intent_digest=h2(intent),source_decision_digest=h2(request['source_decision']),identity_digest=h2(intent['identity']),scope_digest=h2(s),**{k:s[k] for k in ('actor_identity','caller_runtime_id','session_id','lease_id','lease_generation')},admitted_at=at,session_issued_at=at-1,session_expires_at=at+60000,lease_issued_at=at-1,lease_expires_at=at+60000,normal_business_admission=True,core_installation_id=d.core_installation_id,deployment_admission_digest=sha(d.deployment_bytes),component_artifact_digest=sha(d.component_bytes),trust_config_digest=h2(self.pin))
        wire=c2(admission);p=self.folder/('intake-'+intent['operation_id']+'.json')
        content=json.dumps({'request':request_wire.hex(),'source':wire.hex()})
        if p.exists():assert json.loads(p.read_text())==json.loads(content)
        else:p.write_text(content,encoding='ascii')
        return wire
    def _binding(self,request):
        op=request['intent']['operation_id'];pol=next(v for v in self.a['records'].values() if v.get('type')=='recovery_policy' and v['policy_id']==stable(op,'policy'))
        inv=next(v for v in self.a['records'].values() if v.get('type')=='recovery_inventory' and v['inventory_id']==stable(op,'inventory'))
        return {'runtime_principal':self.deployment.runtime_principal,'session_id':inv['session_id'],'policy_digest':h2(pol),'inventory_digest':h2(inv)}
    def caller(self,request):return AuthorityCaller(**self._binding(request))
    def _issue(self,reg,kind,body,target):
        body={'type':kind,'version':2,'contract_revision':2,**body};put(reg,target)
        snap=record('issuance_snapshot',history_version=2,position=pos(reg),issued_at=body['issued_at'],issuance_kind='GRANT' if kind=='execution_grant' else 'PERMIT',issuer_key_id=body['receipt_key_id'],**{k:body[k] for k in ('runtime_principal','session_id','policy_digest','inventory_digest','operation_id','request_digest','source_decision_digest')},restoration_context_digest=body.get('restoration_context_digest'),issue_body_digest=raw(body),fences_or_target_digest=raw(target))
        body.update(issuance_digest=raw(snap),receipt_signature='0'*128);self.sign(body)
        event(reg,'GRANT_ISSUED' if kind=='execution_grant' else 'PERMIT_ISSUED',body['issued_at'],snap,body);return body
    def _sync_authority(self):
        # Privileged test issuance uses actual committed product journal; Core
        # still receives business replies through authenticated pinned HTTPS.
        def read(tx):
            a=registry(self.pin)
            for win in tx.windows:a=merge(a,win.authority)
            return a
        self.a=self.authority_service.store.transact(read)
    def _register(self,request_wire,source_wire,before,reg):
        delta=RegistrySlice(c2(reg['header']),tuple(c2(e) for e in reg['events'][len(before['events']):]),tuple((d,c2(v)) for d,v in reg['records'].items() if d not in before['records']))
        self.authority_service.register_qualification(WindowEvidence((request_wire,),delta,(),source_admission_wires=(source_wire,)))
        self.a=reg
    def ensure_execution(self,request_wire,source_wire):
        self.admit_original(request_wire,source_wire);self._sync_authority();request=decode(request_wire);op=request['intent']['operation_id']
        existing=[v for v in self.a['records'].values() if v.get('type')=='execution_grant' and v['operation_id']==op]
        if existing:
            latest=max(existing,key=lambda v:v['grant_sequence'])
            terminal=any(v.get('type')=='terminal_receipt' and v['operation_id']==op for v in self.a['records'].values())
            if not terminal and latest['expires_at']<now_ms()+12000:
                a=deepcopy(self.a);at=now_ms();body={k:v for k,v in latest.items() if k not in ('type','version','contract_revision','receipt_signature','issuance_digest')}
                body.update(grant_id=stable(op,'grant-'+str(latest['grant_sequence']+1)),grant_sequence=latest['grant_sequence']+1,issued_at=at,expires_at=at+29000)
                fence_event=next(e for e in reversed(a['events']) if e['event_kind']=='FENCES_SET' and a['records'][e['input_digest']]['operation_id']==op)
                fences=a['records'][fence_event['input_digest']]['fences']
                self._issue(a,'execution_grant',body,fences)
                self._register(request_wire,source_wire,self.a,a)
            self._credentials(request);return
        a=deepcopy(self.a);at=now_ms();i=request['intent'];s=i['scope'];ident=i['identity'];d=self.deployment
        common={'operation_id':op,'request_digest':h2(request),'source_decision_digest':h2(request['source_decision'])}
        af={k:self.pin[k] for k in ('authority_domain_id','authority_instance_id','authority_generation')}
        policy=self.sign(obj('recovery_policy',policy_id=stable(op,'policy'),deployment_admission_digest=sha(d.deployment_bytes),**af,**{k:ident[k] for k in ('continuity_id','qingyu_identity_id','genesis_operation_id')},**{k:getattr(d,k) for k in ('core_installation_id','storage_generation_id','control_plane_generation_id','runtime_principal')},component_artifact_digest=sha(d.component_bytes),trust_config_digest=h2(self.pin),restoration_context_digest=None,capabilities=list(ACTIONS),allowed_operation_type='MUTATION',issued_at=at-100,expires_at=at+3600000,operator_root_key_id=self.pin['operator_root_key_id'],root_signature='0'*128))
        enrollment=record('enrollment',**{k:policy[k] for k in ('runtime_principal','core_installation_id','restoration_context_digest','authority_domain_id','authority_instance_id','authority_generation','storage_generation_id','control_plane_generation_id','deployment_admission_digest','component_artifact_digest','trust_config_digest')},policy_digest=h2(policy),context_kind='INTACT_ADMITTED',purpose='MUTATION_RECOVERY',identity_digest=h2(ident))
        session=record('session_binding',history_version=2,session_id=stable(op,'recovery-session'),enrollment=enrollment,issued_at=at,expires_at=at+3600000)
        inventory=obj('recovery_inventory',inventory_id=stable(op,'inventory'),policy_digest=h2(policy),core_installation_id=d.core_installation_id,runtime_principal=d.runtime_principal,session_id=session['session_id'],entries=[{**common,'local_commit_id':i['local_commit_id']}])
        fences=record('fences',**af,identity=ident,owner_identity=s['actor_identity'],owner_version=s['owner_version'],continuity_epoch=s['continuity_epoch'],state_version=s['expected_state_version'],storage_generation_id=s['storage_generation_id'],control_plane_generation_id=s['control_plane_generation_id'],authority_ref=s['expected_authority_ref'],audit_ref=s['expected_audit_ref'])
        event(a,'FENCES_SET',at,record('fence_state',history_version=2,operation_id=op,fences=fences,barrier_operation_id=op,unresolved_operation_ids=[op]))
        for kind,value in (('POLICY_REGISTER',policy),('SESSION_CREATE',session),('INVENTORY_ACCEPT',inventory)):event(a,kind,at,value)
        lease=record('operation_lease',history_version=2,lease_id=stable(op,'recovery-lease'),lease_generation=1,operation_id=op,request_digest=h2(request),runtime_principal=d.runtime_principal,session_id=session['session_id'],issued_at=at,expires_at=at+3600000)
        event(a,'LEASE_CREATE',at,lease)
        binding={'runtime_principal':d.runtime_principal,'session_id':session['session_id'],'policy_digest':h2(policy),'inventory_digest':h2(inventory)}
        self._issue(a,'execution_grant',{'grant_id':stable(op,'grant'),'grant_sequence':1,**binding,**common,**af,**{k:ident[k] for k in ('continuity_id','qingyu_identity_id','genesis_operation_id')},'owner_identity':s['actor_identity'],'owner_version':s['owner_version'],'continuity_epoch':s['continuity_epoch'],'expected_state_version':s['expected_state_version'],'storage_generation_id':s['storage_generation_id'],'control_plane_generation_id':s['control_plane_generation_id'],'lease_id':lease['lease_id'],'lease_generation':1,'issued_at':at,'expires_at':at+29000,'receipt_key_id':self.pin['receipt_key_id']},fences)
        self._register(request_wire,source_wire,self.a,a)
        self._credentials(request)
    def _credentials(self,request):
        import hmac
        op=request['intent']['operation_id'];self.active_op=op
        token=hmac.new(self.config['credential'].encode(),op.encode(),'sha256').hexdigest()
        # One protected independently initialized credential binding per operation.
        value={'token':token,'caller':asdict(self.caller(request))}
        path=self.folder/('credential-'+op+'.json')
        if path.exists():assert json.loads(path.read_text())==value
        else:path.write_text(json.dumps(value),encoding='ascii')
    def credential(self):
        return json.loads((self.folder/('credential-'+self.active_op+'.json')).read_text())['token']
    def refresh(self,reply,request_wire,*,core_history=None,authority_history=None):
        if authority_history is not None:self.a=merge(self.a,authority_history)
        self.a=merge(self.a,reply.authority)
        if core_history is not None:self.core=merge(self.core,core_history)
    def _observe(self,request):
        binding=self._binding(request);at=now_ms()
        kinds={'POLICY_REGISTER':'POLICY_OBSERVED','SESSION_CREATE':'SESSION_OBSERVED','INVENTORY_ACCEPT':'INVENTORY_OBSERVED','PERMIT_ISSUED':'PERMIT_OBSERVED'}
        observed={self.core['records'][e['input_digest']].get('object_digest') for e in self.core['events'] if e['event_kind'] in kinds.values()}
        wanted={binding['policy_digest'],binding['inventory_digest']}
        for value in self.a['records'].values():
            if value.get('session_id')==binding['session_id'] and 'enrollment' in value:wanted.add(raw(value))
            if value.get('type')=='local_finish_permit' and value['operation_id']==request['intent']['operation_id']:wanted.add(h2(value))
        for e in self.a['events']:
            for digest in (e['output_digest'],e['input_digest']):
                value=self.a['records'].get(digest,{})
                kind=kinds.get(e['event_kind'])
                d=(h2(value) if value.get('type') in SCHEMA else raw(value)) if kind else None
                if kind and d in wanted and d not in observed:
                    observation=record('local_observation',history_version=2,authority_position=e['position'],authority_event_digest=raw(e),object_digest=d)
                    event(self.core,kind,at,observation);observed.add(d)
        if not any(e['event_kind']=='LOCAL_PROTECTION' and self.core['records'][e['input_digest']]['policy_digest']==binding['policy_digest'] for e in self.core['events']):
            event(self.core,'LOCAL_PROTECTION',at,record('local_protection',history_version=2,policy_digest=binding['policy_digest'],component_valid=True,policy_active=True,context_kind='INTACT_ADMITTED'))
    def capture(self,operation_id,action,*,local_history=None,authority_history=None):
        from app.r1_atomic_finish import TrustedLocalContext
        if authority_history is not None:self.a=merge(self.a,authority_history)
        if local_history is not None:self.core=merge(self.core,local_history)
        request_wire,_=self.requests.get(operation_id,(None,None))
        if request_wire is None:request_wire=bytes.fromhex(json.loads((self.folder/('intake-'+operation_id+'.json')).read_text())['request'])
        request=decode(request_wire);self._observe(request);b=self._binding(request)
        return TrustedLocalContext(delta(self.a,authority_history),delta(self.core,local_history),checked_at=now_ms(),**b)
    def ensure_permit(self,request_wire,authority_history,core_history):
        self._sync_authority();self.core=merge(self.core,core_history);request=decode(request_wire);op=request['intent']['operation_id']
        permits=[v for v in self.a['records'].values() if v.get('type')=='local_finish_permit' and v['operation_id']==op]
        latest=max(permits,key=lambda v:v['permit_sequence']) if permits else None
        if latest is not None and latest['expires_at']>now_ms()+20000:return
        terminal=next(v for v in self.a['records'].values() if v.get('type')=='terminal_receipt' and v['operation_id']==op)
        selected=request[terminal['decision'].lower()];audit=obj('audit_record',candidate=selected['audit_candidate'],receipt_digest=h2(terminal));s=request['intent']['scope']
        before=obj('local_checkpoint',state_version=s['expected_state_version'],authority_ref=s['expected_authority_ref'],audit_ref=s['expected_audit_ref'])
        after=obj('local_checkpoint',state_version=terminal['state_after'],authority_ref=obj('authority_ref',wire_version=2,authority_generation=terminal['authority_generation'],authority_sequence=terminal['authority_sequence'],receipt_hash=h2(terminal)),audit_ref=obj('audit_ref',wire_version=2,audit_sequence=terminal['audit_sequence'],audit_hash=h2(audit)))
        common={'operation_id':op,'request_digest':h2(request),'source_decision_digest':h2(request['source_decision'])};binding=self._binding(request);at=now_ms()
        target=record('finish_target',history_version=2,identity_digest=h2(request['intent']['identity']),authority_pin_digest=h2(self.pin),core_installation_id=self.deployment.core_installation_id,storage_generation_id=self.deployment.storage_generation_id,control_plane_generation_id=self.deployment.control_plane_generation_id,restoration_context_digest=None,**common,terminal_digest=h2(terminal),before_checkpoint=before,after_checkpoint=after)
        a=deepcopy(self.a)
        sequence=latest['permit_sequence']+1 if latest else 1
        self._issue(a,'local_finish_permit',{'permit_id':stable(op,'permit-'+str(sequence)),'permit_sequence':sequence,**binding,**common,'restoration_context_digest':None,'core_installation_id':self.deployment.core_installation_id,'terminal_digest':h2(terminal),'before_checkpoint':before,'after_checkpoint':after,'issued_at':at,'expires_at':at+29000,'receipt_key_id':self.pin['receipt_key_id']},target)
        source_wire=bytes.fromhex(json.loads((self.folder/('intake-'+op+'.json')).read_text())['source'])
        self._register(request_wire,source_wire,self.a,a)
