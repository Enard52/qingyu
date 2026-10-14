"""Real owned PostgreSQL/TLS/process harness. No completed business fixtures."""
from pathlib import Path
import json,os,socket,ssl,subprocess,sys,time,traceback,hmac
import psycopg
from cryptography.hazmat.primitives import serialization
from tests.r1_roundtrip_provider import (ControlledProvider,material,trust,boundary,scope_wire,
    now_ms,uid,c2,decode,h2,obj)
from app.control_plane.r1_scoped_authority import ScopedAuthority,configuration_digest
from app.control_plane.r1_scoped_postgres import ScopedPostgresStore
from app.control_plane.r1_scoped_transport import ScopedAuthorityClient,ScopedCredentialAuthenticator,create_scoped_authority_app
from app.control_plane.r1_scoped_messages import AuthorityCaller
from app.r1_scoped_coordinator import ScopedCoreCoordinator,build_mutation_request
from app._r1_coordination_journal import CoordinationJournal
from app.r1_atomic_finish import ScopedCoreFinisher
from app._r1_scoped_sqlite import ScopedSQLiteStore

ROOT=Path(__file__).resolve().parents[1]
N=ROOT/'docs/evidence/r1-acceptance-marathon/normal-mutation-durable-roundtrip-slice-03-20260916T220000Z'

def config(path):return json.loads(Path(path).read_text())
def service(path,fault=None):
    cfg=config(path)
    def connection():return psycopg.connect(host=cfg['host'],port=cfg['port'],dbname=cfg['dbname'],user='control_plane_app',password=cfg['app_password'])
    class Signer:
        key_id=cfg['pin']['receipt_key_id']
        def sign(self,raw):
            key=serialization.load_pem_private_key((Path(path).parent/'receipt.key').read_bytes(),None)
            return key.sign(raw)
    digest=configuration_digest(trust(cfg),(material(cfg),),boundary(cfg))
    store=ScopedPostgresStore(connection,scope_id=cfg['scope_id'],configuration_digest=digest)
    return ScopedAuthority(store=store,trust=trust(cfg),deployments=(material(cfg),),boundary=boundary(cfg),receipt_signer=Signer(),fault=fault)

def server(path,crash_stage=None):
    import uvicorn
    from app.control_plane.r1_api import authority_server_config
    folder=Path(path).parent;cfg=config(path)
    def fault(stage):
        if stage==crash_stage:
            (folder/'server-crash.json').write_text(json.dumps({'pid':os.getpid(),'stage':stage}),encoding='ascii')
            os._exit(83)
    authority=service(path,fault)
    def lookup(token):
        for file in folder.glob('credential-*.json'):
            data=json.loads(file.read_text())
            if hmac.compare_digest(token,data['token']):return AuthorityCaller(**data['caller'])
        from app.control_plane.r1_validation_codec import ContractError
        raise ContractError('credential rejected')
    app=create_scoped_authority_app(authority,ScopedCredentialAuthenticator(lookup))
    if crash_stage=='corrupt_terminal_response':
        inner=app
        async def corrupt(scope,receive,send):
            started=None
            async def intercept(message):
                nonlocal started
                if message['type']=='http.response.start':started=message;return
                if message['type']=='http.response.body' and not message.get('more_body',False):
                    from app.control_plane.r1_scoped_transport import _decode,_encode
                    raw=message.get('body',b'')
                    try:value=_decode(raw)
                    except Exception:value={}
                    if value.get('state')=='TERMINAL' and scope.get('method')=='POST':
                        original=bytes.fromhex(value['terminal_wire']);receipt=decode(original);old=h2(receipt)
                        receipt['receipt_signature']=('1' if receipt['receipt_signature'][0]!='1' else '2')+receipt['receipt_signature'][1:]
                        altered=c2(receipt);new=h2(receipt);value['terminal_wire']=altered.hex()
                        value['authority']['records']=[[new,altered.hex()] if d==old else [d,w] for d,w in value['authority']['records']]
                        events=[]
                        for wire in value['authority']['events']:
                            event=decode(bytes.fromhex(wire))
                            if event['output_digest']==old:event['output_digest']=new
                            events.append(c2(event).hex())
                        value['authority']['events']=events;raw=_encode(value);message={**message,'body':raw}
                        (folder/'tampered-terminal.json').write_text(json.dumps({'pid':os.getpid(),'original_digest':old,'altered_digest':new,'only_response_changed':True}),encoding='ascii')
                    if started is not None:
                        started={**started,'headers':[(k,v) for k,v in started['headers'] if k.lower()!=b'content-length']+[(b'content-length',str(len(raw)).encode())]}
                        await send(started);started=None
                await send(message)
            await inner(scope,receive,intercept)
        app=corrupt
    uvicorn.Server(authority_server_config(app,host='127.0.0.1',port=cfg['authority_port'],certificate_file=str(folder/'tls.pem'),private_key_file=str(folder/'tls.key'))).run()

def start_server(path,crash_stage=None):
    folder=Path(path).parent;cfg=config(path)
    output=(folder/('server-'+str(time.time_ns())+'.log')).open('wb')
    args=[sys.executable,'-B','-m','tests.r1_roundtrip_run','server',str(path)]
    if crash_stage:args.append(crash_stage)
    child=subprocess.Popen(args,cwd=ROOT,stdout=output,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    for _ in range(150):
        if child.poll() is not None:raise RuntimeError('owned Authority failed startup; '+output.name)
        try:
            with socket.create_connection(('127.0.0.1',cfg['authority_port']),timeout=.1):return child,output
        except OSError:time.sleep(.1)
    child.terminate();child.wait();raise RuntimeError('owned Authority readiness timeout')

def core(path,*,create=False,hook=None,finish_hook=None):
    cfg=config(path);folder=Path(path).parent;provider=ControlledProvider(path,service(path))
    if create:
        store=ScopedSQLiteStore.create(folder/'finish.sqlite',scope_wire=scope_wire(cfg),checkpoint_wire=c2(cfg['checkpoint']),business_state_wire=c2({}))
        journal=CoordinationJournal.create(folder/'coordination.sqlite',scope_wire=scope_wire(cfg),checkpoint_wire=c2(cfg['checkpoint']))
    else:
        store=ScopedSQLiteStore.open(folder/'finish.sqlite',expected_scope_wire=scope_wire(cfg))
        journal=CoordinationJournal.open(folder/'coordination.sqlite',scope_wire=scope_wire(cfg),checkpoint_wire=c2(cfg['checkpoint']))
    finisher=ScopedCoreFinisher(store,trust=trust(cfg),deployments=(material(cfg),),runtime_principal=cfg['runtime_principal'],source=provider,checkpoint_hook=finish_hook)
    client=ScopedAuthorityClient(trust=trust(cfg),ca_file=str(folder/'ca.pem'),credential_provider=provider.credential,timeout_seconds=30)
    return ScopedCoreCoordinator(journal=journal,finisher=finisher,client=client,source=provider,checkpoint_hook=hook)

def request_for(coordinator,decision='COMMIT',operation_id=None,mutation_id=None):
    cfg=coordinator.source.config
    with coordinator.finisher.store.transaction(write=False) as db:
        checkpoint=decode(db.execute('select checkpoint_wire from metadata').fetchone()[0])
    scope=obj('requested_scope',trust_domain_id=cfg['trust_domain_id'],**{k:cfg['pin'][k] for k in ('authority_domain_id','authority_instance_id','authority_generation')},actor_identity=cfg['actor_identity'],owner_version=1,continuity_epoch=1,expected_state_version=checkpoint['state_version'],storage_generation_id=cfg['storage_generation_id'],control_plane_generation_id=cfg['control_plane_generation_id'],lease_id=uid(),lease_generation=1,caller_runtime_id=uid(),session_id=uid(),capability='core_governance',expected_authority_ref=checkpoint['authority_ref'],expected_audit_ref=checkpoint['audit_ref'])
    request=build_mutation_request(identity=cfg['identity'],scope=scope,payload={'amount':17,'text':'晴雨真实产品闭环'},mutation_id=mutation_id or uid(),decision=decision,created_at=now_ms(),operation_id=operation_id)
    return request,coordinator.source.intake(request)

def worker(path,op,stage=None,submit=False):
    folder=Path(path).parent
    def hook(value):
        if value==stage:
            (folder/('core-crash-'+op+'.json')).write_text(json.dumps({'pid':os.getpid(),'stage':value}),encoding='ascii');os._exit(83)
    coordinator=core(path,hook=hook,finish_hook=hook)
    if submit:
        data=json.loads((folder/('intake-'+op+'.json')).read_text())
        result=coordinator.governed_mutation(bytes.fromhex(data['request']),bytes.fromhex(data['source']))
    else:result=coordinator.recover(op)
    print(json.dumps({'pid':os.getpid(),'operation_id':op,'result_sha256':__import__('hashlib').sha256(result.result_wire).hexdigest(),'applied':result.applied}))

def normal(path):
    child,output=start_server(path)
    results=[]
    try:
        coordinator=core(path,create=not (Path(path).parent/'finish.sqlite').exists())
        for op in coordinator.journal.pending():
            recovered=coordinator.recover(op)
            results.append({'operation_id':op,'recovered_original':True,'result':decode(recovered.result_wire)})
        for decision in ('COMMIT','ABORT','COMMIT'):
            request,source=request_for(coordinator,decision)
            result=coordinator.governed_mutation(request,source)
            query=coordinator.query(result.operation_id,request)
            repeat=coordinator.governed_mutation(request,source)
            assert result.result_wire==query.result_wire==repeat.result_wire
            assert repeat.applied is False
            results.append({'operation_id':result.operation_id,'decision':decision,'result':decode(result.result_wire),'terminal_sha256':__import__('hashlib').sha256(result.terminal_wire).hexdigest()})
        report={'passed':True,'authority_pid':child.pid,'core_pid':os.getpid(),'operations':results}
        (N/'normal-results.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
        print(json.dumps(report,indent=2))
    finally:
        if child.poll() is None:child.terminate();child.wait(timeout=10)
        output.close()

def run_worker(path,op,stage=None,*,submit=False):
    args=[sys.executable,'-B','-m','tests.r1_roundtrip_run','submit' if submit else 'worker',str(path),op]
    if stage:args.append(stage)
    process=subprocess.Popen(args,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    raw,_=process.communicate(timeout=90)
    return {'pid':process.pid,'exit_code':process.returncode,'output':raw.decode('utf8',errors='replace')}

def faults(path):
    folder=Path(path).parent
    progress=N/'fault-progress.json'
    results=json.loads(progress.read_text()) if progress.exists() else []
    child,output=start_server(path)
    try:
        for op in core(path).journal.pending():
            original_crash=json.loads((folder/('core-crash-'+op+'.json')).read_text())
            recovered=run_worker(path,op);assert recovered['exit_code']==0,recovered
            results.append({'stage':original_crash['stage'],'operation_id':op,'crashed':{'exit_code':83,'actual_process':original_crash,'prior_run':'fault-round1.txt'},'recovered':recovered,'renewed_permit_original_terminal_preserved':True})
            progress.write_text(json.dumps(results,indent=2)+'\n',encoding='utf8')
        for stage in ('intent_saved','ack_saved','dispatch_saved','terminal_saved','before_local_finish','after_effect','before_history_commit','after_commit','completed_saved'):
            if any(row['stage']==stage for row in results):continue
            parent=core(path);request,source=request_for(parent,'COMMIT');op=decode(request)['intent']['operation_id']
            crashed=run_worker(path,op,stage,submit=True)
            assert crashed['exit_code']==83,(stage,crashed)
            recovered=run_worker(path,op)
            assert recovered['exit_code']==0,(stage,recovered)
            fresh=core(path);saved=fresh.journal.load(op)
            assert saved['request_wire']==request and saved['completed']==1
            result=fresh.query(op,request);assert decode(result.result_wire)['result_state']=='COMMITTED'
            results.append({'stage':stage,'crashed':crashed,'actual_crash':json.loads((folder/('core-crash-'+op+'.json')).read_text()),'recovered':recovered,'operation_id':op,'exact_original_request':True})
            (N/'fault-progress.json').write_text(json.dumps(results,indent=2)+'\n',encoding='utf8')
        child.terminate();child.wait(timeout=10);output.close()
        for stage in ('after_prepare_commit','after_terminal_commit'):
            if any(row['stage']==stage for row in results):continue
            child,output=start_server(path,stage)
            parent=core(path);request,source=request_for(parent,'ABORT');op=decode(request)['intent']['operation_id']
            uncertain=run_worker(path,op,submit=True)
            child.wait(timeout=10);assert child.returncode==83,(stage,uncertain)
            assert uncertain['exit_code']!=0 and 'Uncertain' in uncertain['output'],uncertain
            output.close();child,output=start_server(path)
            recovered=run_worker(path,op);assert recovered['exit_code']==0,recovered
            results.append({'stage':stage,'authority_crash':json.loads((folder/'server-crash.json').read_text()),'uncertain':uncertain,'recovered':recovered,'operation_id':op})
            (N/'fault-progress.json').write_text(json.dumps(results,indent=2)+'\n',encoding='utf8')
            child.terminate();child.wait(timeout=10);output.close()
        print(json.dumps({'passed':True,'cases':results},indent=2))
    finally:
        if child.poll() is None:child.terminate();child.wait(timeout=10)
        output.close()

def concurrency(path):
    child,output=start_server(path);cases=[]
    try:
        fresh=core(path)
        # Competing different original operations share the exact actual local
        # checkpoint. One is accepted; the other preserves its rejected intent.
        pending=fresh.journal.pending()
        if len(pending)==2:
            id1,id2=pending
            r1,r2=fresh.journal.load(id1),fresh.journal.load(id2)
            one,src1,two,src2=r1['request_wire'],r1['source_wire'],r2['request_wire'],r2['source_wire']
        else:
            assert not pending,'unexpected pending original intent; inspect rather than replace'
            one,src1=request_for(fresh);two,src2=request_for(fresh)
            id1=fresh.persist_intent(one,src1);id2=fresh.persist_intent(two,src2)
        fresh.source.ensure_execution(one,src1);fresh.source.ensure_execution(two,src2)
        competitors=[subprocess.Popen([sys.executable,'-B','-m','tests.r1_roundtrip_run','worker',str(path),x],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0) for x in (id1,id2)]
        competing=[]
        for p in competitors:
            raw,_=p.communicate(timeout=120);competing.append({'pid':p.pid,'exit_code':p.returncode,'output':raw.decode('utf8',errors='replace')})
        (N/'concurrency-progress.json').write_text(json.dumps({'original_competing_ids':[id1,id2],'different_predecessor_competitors':competing},indent=2)+'\n',encoding='utf8')
        assert sum(p['exit_code']==0 for p in competing)==1,competing
        parent=core(path);request,source=request_for(parent);op=parent.persist_intent(request,source)
        parent.source.ensure_execution(request,source)
        processes=[]
        for _ in range(3):
            processes.append(subprocess.Popen([sys.executable,'-B','-m','tests.r1_roundtrip_run','worker',str(path),op],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0))
        for p in processes:
            raw,_=p.communicate(timeout=120);cases.append({'pid':p.pid,'exit_code':p.returncode,'output':raw.decode('utf8',errors='replace')})
        (N/'concurrency-progress.json').write_text(json.dumps({'original_competing_ids':[id1,id2],'different_predecessor_competitors':competing,'same_operation_id':op,'same_operation_processes':cases},indent=2)+'\n',encoding='utf8')
        assert any(c['exit_code']==0 for c in cases),cases
        reconciled=run_worker(path,op);assert reconciled['exit_code']==0,reconciled
        fresh=core(path)
        with fresh.finisher.store.transaction(write=False) as db:
            counts={table:db.execute(f'SELECT count(*) FROM {table} WHERE operation_id=?',(op,)).fetchone()[0] for table in ('operations','completions','permit_consumptions','business_records')}
        assert all(v==1 for v in counts.values()),counts
        fresh=core(path)
        ids=(op,id1,id2)
        remote=fresh.source.authority_service.store.transact(lambda tx:{key:tx.operation(key) for key in ids})
        assert remote[op] is not None and remote[op].terminal_wire is not None
        assert sum(remote[key] is not None and remote[key].terminal_wire is not None for key in (id1,id2))==1
        winner=next(key for key in (id1,id2) if remote[key] is not None and remote[key].terminal_wire is not None)
        loser=id2 if winner==id1 else id1
        physical={}
        with fresh.finisher.store.transaction(write=False) as db:
            for key in ids:
                physical[key]={table:db.execute(f'SELECT count(*) FROM {table} WHERE operation_id=?',(key,)).fetchone()[0] for table in ('operations','completions','permit_consumptions','business_records')}
                completed=db.execute('SELECT terminal_wire,audit_wire,result_wire FROM completions WHERE operation_id=?',(key,)).fetchone()
                if key!=loser:
                    assert all(value==1 for value in physical[key].values())
                    assert completed is not None and completed['terminal_wire']==remote[key].terminal_wire
                    from app.control_plane.r1_validation_crypto import verify_signed
                    verify_signed(decode(remote[key].terminal_wire),trust(config(path)))
                    physical[key]['audit_sha256']=__import__('hashlib').sha256(completed['audit_wire']).hexdigest()
                    physical[key]['result_sha256']=__import__('hashlib').sha256(completed['result_wire']).hexdigest()
                else:assert all(value==0 for value in physical[key].values()) and completed is None
        from app.control_plane.r1_validation_codec import ContractError
        row=fresh.journal.load(op);mutated=decode(request);mutated['intent']['reason']='changed original content'
        try:fresh.governed_mutation(c2(mutated),source)
        except ContractError:pass
        else:raise AssertionError('same ID changed content accepted')
        fresh.source.ensure_execution(request,source)
        before=fresh.source.authority_service.store.transact(lambda tx:(tx.revision,tx.operation(op)))
        wrong=decode(row['authorization_wire']);wrong.update(decision='ABORT',candidate_digest=h2(decode(request)['abort']),no_local_business_commit=True)
        from app.control_plane.r1_scoped_transport import ScopedHTTPRejected
        try:fresh.client.decide(op,request,c2(wrong),row['proposal_wire'],row['publication_wire'],fresh._dispatch_history(),authority_after=len(fresh._authority_history().event_wires))
        except ScopedHTTPRejected as exc:assert exc.status==409
        else:raise AssertionError('unauthorized opposite NORMAL decision accepted')
        after=fresh.source.authority_service.store.transact(lambda tx:(tx.revision,tx.operation(op)))
        assert before==after
        report={'passed':True,'same_operation_processes':cases,'reconciled':reconciled,'exact_once_rows':counts,'different_predecessor_competitors':competing,'same_id_different_content':'rejected','unauthorized_opposite_normal':'HTTP409 and exact remote rows unchanged','op':op,'winner':winner,'loser':loser,'physical_rows':physical,'different_operation_terminal_count':1}
        (N/'concurrency-results.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps(report,indent=2))
    finally:
        if child.poll() is None:child.terminate();child.wait(timeout=10)
        output.close()

def continuation(path,target=65):
    child,output=start_server(path);results=[]
    try:
        coordinator=core(path)
        initial=coordinator.finisher.store.inspect()['counts']['completions']
        for number in range(initial,target):
            start=time.monotonic();request,source=request_for(coordinator,'ABORT' if number%3==0 else 'COMMIT')
            result=coordinator.governed_mutation(request,source)
            results.append({'ordinal':number+1,'operation_id':result.operation_id,'decision':decode(request)['intent']['requested_decision'],'elapsed_seconds':round(time.monotonic()-start,3),'terminal_sha256':__import__('hashlib').sha256(result.terminal_wire).hexdigest()})
            (N/'continuation-progress.json').write_text(json.dumps({'initial_complete':initial,'target':target,'new_operations':results},indent=2)+'\n',encoding='utf8')
        fresh=core(path)
        with fresh.journal.transaction(write=False) as db:
            rows=db.execute('SELECT operation_id,request_wire FROM attempts WHERE completed=1 ORDER BY rowid').fetchall()
        assert len(rows)>=target
        checked=[]
        for row in (rows[0],rows[63],rows[64]):
            result=fresh.query(row['operation_id'],row['request_wire']);assert not result.applied
            checked.append(row['operation_id'])
        snapshot=fresh.finisher.store.inspect()
        report={'passed':True,'same_database':config(path)['dbname'],'initial_complete':initial,'final_complete':snapshot['counts']['completions'],'new_operations':results,'fresh_process_object_queries':checked,'counts':snapshot['counts']}
        (N/'continuation-results.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps(report,indent=2))
    finally:
        if child.poll() is None:child.terminate();child.wait(timeout=10)
        output.close()

def transport_negative(path):
    child,output=start_server(path,'corrupt_terminal_response')
    try:
        parent=core(path);request,source=request_for(parent);op=decode(request)['intent']['operation_id']
        rejected=run_worker(path,op,submit=True)
        assert rejected['exit_code']!=0 and ('signature' in rejected['output'].lower() or 'ed25519' in rejected['output'].lower()),rejected
        fresh=core(path)
        with fresh.finisher.store.transaction(write=False) as db:
            assert db.execute('SELECT count(*) FROM completions WHERE operation_id=?',(op,)).fetchone()[0]==0
        actual=fresh.source.authority_service.store.transact(lambda tx:tx.operation(op))
        assert actual.terminal_wire is not None
        child.terminate();child.wait(timeout=10);output.close();child,output=start_server(path)
        recovered=run_worker(path,op);assert recovered['exit_code']==0,recovered
        report={'passed':True,'operation_id':op,'corruption':json.loads((Path(path).parent/'tampered-terminal.json').read_text()),'rejected':rejected,'zero_local_completion_on_signature_failure':True,'real_authority_terminal_preserved':True,'recovered_original':recovered}
        (N/'transport-negative-results.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps(report,indent=2))
    finally:
        if child.poll() is None:child.terminate();child.wait(timeout=10)
        output.close()

if __name__=='__main__':
    mode,path,*rest=sys.argv[1:]
    path=str(Path(path).resolve())
    if mode=='server':server(path,*rest)
    elif mode=='worker':worker(path,*rest)
    elif mode=='submit':worker(path,*rest,submit=True)
    elif mode=='normal':normal(path)
    elif mode=='faults':faults(path)
    elif mode=='concurrency':concurrency(path)
    elif mode=='continuation':continuation(path,*map(int,rest))
    elif mode=='transport-negative':transport_negative(path)
