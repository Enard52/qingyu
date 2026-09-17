"""Retest a preserved losing intent after its original competitor completed."""
from pathlib import Path
import hashlib,json,sys
from tests.r1_roundtrip_run import core,start_server,N
from app.control_plane.r1_validation_codec import ContractError,decode
from app.control_plane.r1_scoped_transport import ScopedHTTPRejected

def run(path,op):
    path=Path(path).resolve();child,output=start_server(path)
    try:
        coordinator=core(path);row=coordinator.journal.load(op)
        original=row['request_wire'];source=row['source_wire']
        try:coordinator.recover(op)
        except ScopedHTTPRejected as exc:
            assert exc.status==409
            http={'status':exc.status,'error':str(exc)}
        else:raise AssertionError('old predecessor accepted')
        authority=coordinator.source.authority_service
        coordinator.source.ensure_execution(original,source)
        before=authority.store.transact(lambda tx:(tx.revision,tx.operation(op)))
        try:authority.prepare(original,source,coordinator.source.caller(decode(original)))
        except ContractError as exc:
            assert str(exc)=='current predecessor differs',str(exc)
            reason=str(exc)
        else:raise AssertionError('old predecessor accepted by Authority')
        after=authority.store.transact(lambda tx:(tx.revision,tx.operation(op)))
        assert before==after and after[1] is None
        assert coordinator.journal.load(op)['request_wire']==original
        with coordinator.finisher.store.transaction(write=False) as db:
            counts={t:db.execute(f'SELECT count(*) FROM {t} WHERE operation_id=?',(op,)).fetchone()[0]
                    for t in ('operations','completions','permit_consumptions','business_records')}
        assert all(n==0 for n in counts.values())
        result={'passed':True,'original_operation_id':op,'original_request_sha256':hashlib.sha256(original).hexdigest(),
                'core_real_http_recovery_rejected':http,'product_authority_reason':reason,
                'authority_revision_unchanged_on_rejected_prepare':before[0],
                'authority_business_row_absent':True,'local_rows':counts,
                'qualification_renewal':'legal test grant issued before rejection snapshots; not counted as a business fact'}
        (N/'loser-recheck-results.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
        print(json.dumps(result,indent=2))
    finally:
        if child.poll() is None:child.terminate();child.wait(timeout=10)
        output.close()

if __name__=='__main__':run(*sys.argv[1:])
