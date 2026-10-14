"""Synthetic governance objects only; no real second Owner decision is made."""
from dataclasses import replace, FrozenInstanceError
from types import SimpleNamespace
import ast
import json
import os
from pathlib import Path

import pytest

from app.b2_genesis_authorization import (GenesisAuthorizationEvidence, GenesisAuthorizationContext,
    GenesisAuthorizationVerifier, VerifiedGenesisAuthorization, NON_PRODUCTION, PRODUCTION,
    FOUNDATION_CHECKPOINT, genesis_authorization_context, git_object_id)
from app.b2_signer_trust import AuthorityEnvironmentMode
from app.control_plane.r1_validation_codec import c2, decode, sha
from app.errors import CoreError
from app.r1_scoped_activation_core import ScopedV2PostgresCore
from tests.test_b2_activation_lifecycle import pg, scenario, dependencies, call, table_bytes, resigned_proof


def anchored(body):
    """In-memory NON_PRODUCTION Git object fixtures; never written to Git."""
    wire = c2(body)
    marker = 'OWNER_GENESIS_APPROVAL_SHA256: ' + sha(wire)
    commit = ('tree ' + '0'*40 + '\nauthor NON_PRODUCTION <synthetic@example.invalid> 1 +0000\n'
        'committer NON_PRODUCTION <synthetic@example.invalid> 1 +0000\n\nNON_PRODUCTION fixture\n' + marker+'\n').encode()
    checkpoint = git_object_id('commit',commit)
    tag = ('object '+checkpoint+'\ntype commit\ntag NON_PRODUCTION-owner-fixture\n'
        'tagger NON_PRODUCTION <synthetic@example.invalid> 1 +0000\n\nNON_PRODUCTION fixture\n'+marker+'\n').encode()
    evidence = GenesisAuthorizationEvidence(wire,commit,tag)
    verifier = GenesisAuthorizationVerifier(NON_PRODUCTION,checkpoint,git_object_id('tag',tag),sha(wire),body['foundation_checkpoint'])
    return evidence,verifier


def args(s):
    return dict(authority_reference=s.target.authority_reference,intent_id=s.intent.intent_id,
                opening=s.proof,owner_approval=s.approval)


@pytest.fixture
def authorized(scenario):
    s=scenario;dependencies(s)
    # Trusted test composition configures its synthetic checkpoint pins.
    s.core._genesis_authorization_verifier=GenesisAuthorizationVerifier(NON_PRODUCTION,'0'*40,'1'*40,'2'*64,'NON_PRODUCTION:foundation-fixture')
    context=genesis_authorization_context(s.core,**args(s))
    body={**decode(context.wire),'schema_version':'qingyu-genesis-owner-authorization-v1',
          'decision':'APPROVE_SYNTHETIC_V2_NEW_GENESIS',
          'provenance':{'version':'thread-owner-checkpoint-v1','authorization_reference':'NON_PRODUCTION:owner-fixture','authorization_sha256':'3'*64}}
    evidence,verifier=anchored(body);s.core._genesis_authorization_verifier=verifier
    s.core.recovery_verifier=lambda: None
    return s,evidence,context,verifier


def test_verified_synthetic_capability_preflight_continuation_replay(authorized):
    s,e,c,v=authorized
    with pytest.raises(CoreError):call(s,authorization=e)
    assert table_bytes(s)==(None,None,None)
    cap=v.verify(e,c)
    assert type(cap) is VerifiedGenesisAuthorization
    assert s.core.final_owner_confirmation_gate(**args(s),now=s.now,authorization=cap)=={'status':'AUTHORIZATION_VERIFIED_FOR_CONTINUATION'}
    assert table_bytes(s)==(None,None,None)
    result=call(s,authorization=cap);assert result['outcome']=='GENESIS_DURABLE'
    assert result['genesis_hash']==decode(c.wire)['genesis_request_hash']
    before=table_bytes(s);assert call(s,authorization=cap)['outcome']=='GENESIS_ALREADY_DURABLE';assert table_bytes(s)==before
    destination=os.environ.get('QINGYU_AUTHORIZATION_CASE_EVIDENCE')
    if destination:
        Path(destination).write_text(json.dumps({'classification':NON_PRODUCTION,'owner_checkpoint':v.owner_checkpoint,
            'owner_tag_object':v.owner_tag_object,'approval_sha256':v.approval_sha256,
            'request_hash':decode(c.wire)['genesis_request_hash'],'context_hash':cap.context_hash,
            'first':'GENESIS_DURABLE','second':'GENESIS_ALREADY_DURABLE','root_rows_unchanged':True,
            'real_approval_created':False},indent=2),encoding='utf-8')


@pytest.mark.parametrize('bad',[None,True,False,'YES','APPROVE_REAL_V2_NEW_GENESIS',{},object()])
def test_real_gate_has_no_boolean_string_or_dict_bypass_without_DB(bad):
    # Unit gate context only. No real adapter/store is constructed or connected.
    fake=SimpleNamespace(mode=AuthorityEnvironmentMode.REAL_PRODUCTION,genesis_authorization_verifier=None)
    fake._verify_genesis_authorization=lambda value,**kw: ScopedV2PostgresCore._verify_genesis_authorization(fake,value,**kw)
    with pytest.raises(CoreError,match='GENESIS_FINAL_OWNER_CONFIRMATION_REQUIRED'):
        ScopedV2PostgresCore.execute_new_genesis(fake,authority_reference='NON_PRODUCTION:unread',
            intent_id='NON_PRODUCTION:unread',opening=None,owner_approval=None,now=None,authorization=bad)


@pytest.mark.parametrize('field,expected',[
    ('decision','OWNER_DECISION'),('foundation_checkpoint','FOUNDATION_CHECKPOINT'),
    ('activation_request_hash','ACTIVATION_REQUEST'),('authority_reference','AUTHORITY'),('authority_hash','AUTHORITY'),
    ('intent_id','SMI'),('smi_hash','SMI'),('genesis_request_hash','GENESIS_REQUEST'),
    ('target_database','TARGET'),('environment','ENVIRONMENT'),('adapter','ADAPTER')])
def test_checkpointed_approval_must_match_exact_current_context(authorized,field,expected):
    s,e,c,v=authorized;body=decode(e.approval_wire);body[field]='NON_PRODUCTION:wrong'
    if field=='foundation_checkpoint':body[field]='NON_PRODUCTION:other-foundation'
    bad,other=anchored(body)
    # Even if a different approval is anchored, it cannot authorize this context.
    with pytest.raises(CoreError,match=expected):other.verify(bad,c)
    assert table_bytes(s)==(None,None,None)


@pytest.mark.parametrize('part',['commit','tag','wire'])
def test_wrong_checkpoint_or_unanchored_approval_rejected(authorized,part):
    s,e,c,v=authorized
    bad=replace(e,**{'checkpoint_commit_wire' if part=='commit' else 'checkpoint_tag_wire' if part=='tag' else 'approval_wire':
        e.checkpoint_commit_wire+b'changed' if part=='commit' else e.checkpoint_tag_wire+b'changed' if part=='tag' else c2({**decode(e.approval_wire),'decision':'wrong'})})
    with pytest.raises(CoreError):v.verify(bad,c)
    assert table_bytes(s)==(None,None,None)


def test_request_A_capability_cannot_execute_request_B(authorized):
    s,e,c,v=authorized;cap=v.verify(e,c)
    with pytest.raises(CoreError,match='GENESIS_REQUEST_MISMATCH'):
        call(s,opening=resigned_proof(s,reason='NON_PRODUCTION request B'),authorization=cap)
    assert table_bytes(s)==(None,None,None)


@pytest.mark.parametrize('attack',['constructor','context_hash','evidence','empty','different_anchor'])
def test_forged_capability_requires_reverifiable_evidence(authorized,attack):
    s,e,c,v=authorized
    if attack=='constructor':
        with pytest.raises(CoreError,match='VERIFIER_REQUIRED'):VerifiedGenesisAuthorization(evidence=e,context_hash=sha(c.wire))
        return
    cap=v.verify(e,c)
    if attack=='context_hash':object.__setattr__(cap,'context_hash','0'*64)
    if attack=='evidence':object.__setattr__(cap,'evidence',replace(e,checkpoint_tag_wire=e.checkpoint_tag_wire+b'changed'))
    if attack=='empty':cap=object.__new__(VerifiedGenesisAuthorization)
    if attack=='different_anchor':s.core._genesis_authorization_verifier=replace(v,owner_checkpoint='f'*40)
    with pytest.raises(CoreError):call(s,authorization=cap)
    assert table_bytes(s)==(None,None,None)


def test_synthetic_capability_cannot_unlock_real_unit_context(authorized):
    s,e,c,v=authorized;cap=v.verify(e,c)
    fake=SimpleNamespace(mode=AuthorityEnvironmentMode.REAL_PRODUCTION,genesis_authorization_verifier=v)
    with pytest.raises(CoreError,match='CLASSIFICATION_MISMATCH'):
        ScopedV2PostgresCore._verify_genesis_authorization(fake,cap,**args(s))


@pytest.mark.parametrize('field,value',[('target_database','qingyu_prod'),('target_database','qingyu_control'),('environment','PRODUCTION')])
def test_synthetic_governance_cannot_target_production_names(authorized,field,value):
    s,e,c,v=authorized;body=decode(e.approval_wire);body[field]=value;bad,other=anchored(body)
    context=GenesisAuthorizationContext(c2({**decode(c.wire),field:value}))
    with pytest.raises(CoreError,match='TARGET_MISMATCH'):other.verify(bad,context)


def test_real_shaped_verifier_cannot_validate_synthetic_context(authorized):
    s,e,c,v=authorized
    # Only verifier configuration is real-shaped; no PRODUCTION approval is made.
    real=GenesisAuthorizationVerifier(PRODUCTION,v.owner_checkpoint,v.owner_tag_object,v.approval_sha256,FOUNDATION_CHECKPOINT)
    with pytest.raises(CoreError):real.verify(e,c)
    with pytest.raises(CoreError,match='FOUNDATION_CHECKPOINT'):
        replace(real,foundation_checkpoint='0'*40)


def test_authorization_is_immutable_public_metadata(authorized):
    s,e,c,v=authorized;cap=v.verify(e,c)
    with pytest.raises(FrozenInstanceError):cap.context_hash='0'*64
    with pytest.raises(FrozenInstanceError):e.approval_wire=b'changed'
    with pytest.raises(CoreError):v.verify({'approval_wire':e.approval_wire},c)
    with pytest.raises(AttributeError):s.core.genesis_authorization_verifier=v


@pytest.mark.parametrize('part',['commit','tag'])
def test_hash_consistent_checkpoint_still_requires_approval_anchor(authorized,part):
    s,e,c,v=authorized
    marker=('OWNER_GENESIS_APPROVAL_SHA256: '+v.approval_sha256).encode()
    if part=='commit':
        commit=e.checkpoint_commit_wire.replace(marker,b'NON_PRODUCTION:no-approval-anchor')
        checkpoint=git_object_id('commit',commit)
        tag=e.checkpoint_tag_wire.replace(v.owner_checkpoint.encode(),checkpoint.encode())
        bad=replace(e,checkpoint_commit_wire=commit,checkpoint_tag_wire=tag)
        verifier=replace(v,owner_checkpoint=checkpoint,owner_tag_object=git_object_id('tag',tag))
    else:
        tag=e.checkpoint_tag_wire.replace(marker,b'NON_PRODUCTION:no-approval-anchor')
        bad=replace(e,checkpoint_tag_wire=tag);verifier=replace(v,owner_tag_object=git_object_id('tag',tag))
    with pytest.raises(CoreError,match='OWNER_CHECKPOINT_MISMATCH'):verifier.verify(bad,c)


def test_original_transaction_and_all_unrelated_methods_are_AST_identical():
    import subprocess
    old=ast.parse(subprocess.check_output(['git','show','HEAD:app/r1_scoped_activation_core.py'],text=True))
    new=ast.parse(Path('app/r1_scoped_activation_core.py').read_text('utf-8-sig'))
    def methods(tree):
        return {n.name:n for node in tree.body if isinstance(node,ast.ClassDef) for n in node.body if isinstance(n,ast.FunctionDef)}
    a,b=methods(old),methods(new)
    assert [ast.dump(n,include_attributes=False) for n in a['execute_new_genesis'].body[1:]]==[ast.dump(n,include_attributes=False) for n in b['execute_new_genesis'].body[2:]]
    for name in set(a)-{'__init__','execute_new_genesis','final_owner_confirmation_gate'}:
        assert ast.dump(a[name],include_attributes=False)==ast.dump(b[name],include_attributes=False)


def test_protected_real_valid_capability_uses_same_transaction_structurally():
    # No real approval or REAL domain call. Prove gate falls through into the
    # unchanged body, and has no synthetic-mode flip/second transaction path.
    tree=ast.parse(Path('app/r1_scoped_activation_core.py').read_text('utf-8-sig'))
    method=next(n for c in tree.body if isinstance(c,ast.ClassDef) for n in c.body if isinstance(n,ast.FunctionDef) and n.name=='execute_new_genesis')
    assert method.body[0].test.op.__class__ is ast.And
    assert isinstance(method.body[1],ast.If)
    assert not any(isinstance(n,(ast.Return,ast.Raise,ast.Assign)) for n in ast.walk(method.body[1]))
    assert sum(isinstance(n,ast.With) for n in ast.walk(method))==1


def test_authorized_commit_uncertainty_keeps_readonly_reconciliation(authorized,monkeypatch):
    import psycopg
    s,e,c,v=authorized;cap=v.verify(e,c);original=s.core.engine.dialect.do_commit
    def lose(connection):original(connection);raise psycopg.OperationalError('NON_PRODUCTION response lost')
    with monkeypatch.context() as m:
        m.setattr(s.core.engine.dialect,'do_commit',lose)
        with pytest.raises(CoreError,match='OUTCOME_UNKNOWN_RECONCILIATION_REQUIRED'):call(s,authorization=cap)
    state=s.core.verify_core_identity();before=table_bytes(s)
    assert s.core.reconcile_new_genesis(state['genesis_hash'])=='EXACT';assert before==table_bytes(s)
    assert call(s,authorization=cap)['outcome']=='GENESIS_ALREADY_DURABLE'


@pytest.mark.parametrize('bad',['empty','list','context','nonbytes','provenance'])
def test_malformed_evidence_and_context_fail_precisely(authorized,bad):
    s,e,c,v=authorized
    if bad=='empty':e=replace(e,approval_wire=b'')
    if bad=='list':e=replace(e,approval_wire=c2([]))
    if bad=='context':c=GenesisAuthorizationContext(c2({}))
    if bad=='nonbytes':e=replace(e,approval_wire='untrusted string')
    if bad=='provenance':
        body=decode(e.approval_wire);body['provenance']['authorization_reference']='postgresql://user:PASSWORD@example.invalid/db';e,v=anchored(body)
    with pytest.raises(CoreError,match='MALFORMED_APPROVAL'):v.verify(e,c)
    assert table_bytes(s)==(None,None,None)


def test_authorization_survives_restart_without_one_time_process_token(authorized):
    s,e,c,v=authorized;cap=v.verify(e,c);first=call(s,authorization=cap);before=table_bytes(s)
    s.core.engine.dispose()
    restarted=ScopedV2PostgresCore(s.url(s.core_db),database=s.core_db,control=s.control,
        configuration=s.configuration,mode=AuthorityEnvironmentMode.SYNTHETIC_PRODUCTION_TEST,
        genesis_authorization_verifier=replace(v))
    try:
        rebuilt=genesis_authorization_context(restarted,**args(s));newcap=restarted.genesis_authorization_verifier.verify(replace(e),rebuilt)
        assert restarted.execute_new_genesis(**args(s),now=s.now,authorization=newcap)['outcome']=='GENESIS_ALREADY_DURABLE'
        assert restarted.verify_core_identity()['identity_hash']==first['identity_hash'];assert table_bytes(s)==before
    finally:restarted.engine.dispose()
