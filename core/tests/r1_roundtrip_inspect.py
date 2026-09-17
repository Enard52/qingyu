"""Read back exact owned product facts; no fixture repair or business writes."""
from pathlib import Path
import hashlib,json,sys
from tests.r1_roundtrip_run import core,N
from app.r1_atomic_finish import _unpack
from app.control_plane.r1_validation_codec import c2,decode,h2,obj
from app.control_plane.r1_validation_crypto import verify_signed

def inspect(path):
    coordinator=core(Path(path).resolve());authority=coordinator.source.authority_service
    def remote(tx):
        engine=authority._engine(tx)
        return engine,{op:tx.operation(op) for op in engine.requests},tuple(tx.window_wires) if hasattr(tx,'window_wires') else ()
    ae,operations,_=authority.store.transact(remote)
    rows=[];windows=[]
    with coordinator.finisher.store.transaction(write=False) as db:
        originals=db.execute('SELECT * FROM history_windows ORDER BY sequence').fetchall()
        engine=coordinator.finisher._engine(db,_unpack(originals[0]['evidence_wire']))
        for record in originals:
            proof=_unpack(record['evidence_wire']);stats=decode(record['verification_wire'])
            windows.append({'sequence':record['sequence'],'bytes':len(record['evidence_wire']),'sha256':hashlib.sha256(record['evidence_wire']).hexdigest(),'statistics':stats})
        completed=db.execute('SELECT * FROM completions ORDER BY operation_id').fetchall()
        for item in completed:
            op=item['operation_id'];stored=operations[op];request=decode(stored.request_wire);terminal=decode(stored.terminal_wire)
            verify_signed(terminal,authority.trust)
            assert all(getattr(stored,k) is not None for k in ('ack_wire','authorization_wire','proposal_wire','acceptance_wire','publication_wire','terminal_wire'))
            intent=coordinator.journal.load(op)
            for name in ('request_wire','source_wire','ack_wire','authorization_wire','proposal_wire','acceptance_wire','publication_wire','terminal_wire'):
                assert intent[name]==getattr(stored,name),(op,name)
            local_operation=db.execute('SELECT request_wire,status FROM operations WHERE operation_id=?',(op,)).fetchone()
            assert local_operation['request_wire']==stored.request_wire and local_operation['status']=='FINALIZED'
            assert item['terminal_wire']==stored.terminal_wire
            branch=request[terminal['decision'].lower()]
            audit=obj('audit_record',candidate=branch['audit_candidate'],receipt_digest=h2(terminal))
            assert item['audit_wire']==c2(audit) and item['result_wire']==c2(branch['result'])
            assert item['effect_wire']==c2(branch['effect'])
            uses=db.execute('SELECT permit_digest,local_event_position FROM permit_consumptions WHERE operation_id=?',(op,)).fetchall()
            count=len(uses);assert count==1
            assert uses[0]['permit_digest']==h2(decode(item['permit_wire']))
            business=db.execute('SELECT value_wire FROM business_records WHERE operation_id=?',(op,)).fetchall()
            assert len(business)==(1 if terminal['decision']=='COMMIT' else 0)
            if business:assert business[0][0]==c2(branch['effect']['entries'][0]['value'])
            assert engine.core_states[coordinator.runtime_principal]['completions'][op]==decode(item['completion_wire'])
            assert ae.authority_state['terminals'][op]==terminal
            rows.append({'operation_id':op,'decision':terminal['decision'],'request_sha256':hashlib.sha256(stored.request_wire).hexdigest(),'terminal_sha256':hashlib.sha256(stored.terminal_wire).hexdigest(),'authority_sequence':terminal['authority_sequence'],'audit_sequence':terminal['audit_sequence'],'state_before':terminal['state_before'],'state_after':terminal['state_after'],'permit_consumptions':count,'business_rows':len(business)})
        checkpoint=decode(db.execute('SELECT checkpoint_wire FROM metadata').fetchone()[0])
        assert checkpoint==engine.core_checkpoints[coordinator.runtime_principal]
    assert len(ae.authority_state['terminals'])==len(rows)
    with coordinator.journal.transaction(write=False) as db:
        local=coordinator._engine(db)
        attempts=db.execute('SELECT operation_id,completed FROM attempts').fetchall()
        unfinished=[r[0] for r in attempts if not r[1]]
        facts=[]
        for r in db.execute('SELECT sequence,evidence_wire FROM windows ORDER BY sequence'):
            p=_unpack(r['evidence_wire']);w=p.evidence
            facts.append({'sequence':r['sequence'],'sha256':hashlib.sha256(r['evidence_wire']).hexdigest(),'bytes':len(r['evidence_wire']),'requests':len(w.request_wires),'authority_events':len(w.authority.event_wires),'authority_records':len(w.authority.record_wires),'core_events':sum(len(v.event_wires) for _,v in w.cores),'core_records':sum(len(v.record_wires) for _,v in w.cores)})
    report={'passed':True,'database':coordinator.source.config['dbname'],'actual_terminal_count':len(rows),'actual_completed_count':len(rows),'actual_requested_count':len(operations),'core_pending_original_ids':unfinished,'authority_registry_position':len(ae.authority['events']),'core_registry_position':len(engine.cores[coordinator.runtime_principal]['events']),'checkpoint':checkpoint,'operations':rows,'finisher_windows':windows,'coordination_windows':facts,'max_coordination_requests_per_window':max(r['requests'] for r in facts),'max_authority_delta_events':max(r['authority_events'] for r in facts),'max_core_delta_events':max(r['core_events'] for r in facts),'exact_phase_bytes_checked':['request','source','ack','authorization','proposal','acceptance','publication','terminal'],'statement':'Actual owned main database only; previous Slice02 129 operations are not included. This is readback, not a new set of business operations.'}
    (N/'physical-summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('operations','finisher_windows','coordination_windows')},indent=2))

if __name__=='__main__':inspect(sys.argv[1])
