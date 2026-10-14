"""Bounded operational composition of the frozen B2 capabilities.

No CLI loads engines, policy pins, credentials or signer keys from a request.
Deployment composition owns those dependencies. Python object visibility is not
a security boundary against hostile code in the deployment process. None of the
prepared values below is a governance capability. All writes have fresh preflight,
distinct consent, one send, and read-only reconciliation after uncertainty.
"""
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import os

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from pydantic import ValidationError

from app.errors import CoreError
from app.control_plane.r1_validation_codec import c2, decode, sha, ContractError
from app.b2_activation_readiness import SignedMigrationIntent, OwnerApproval, validate_owner_approval
from app.b2_activation_lifecycle import activation_hash
from app.b2_signer_trust import (AuthorityEnvironmentMode, SignerProviderClassification,
    sign_smi_payload, _trust_record_hash, _admission_record_hash, ensure_production_eligible)
from app.b2_migration_authorization import (
    ProtectedMigrationTarget, PreparedMigrationPlan, REAL_PRODUCTION, SYNTHETIC_TEST,
    VerifiedProductionMigrationAuthorization,
)
from app.control_plane.b2_activation_schema import (
    apply_activation_migration, CONTROL_REVISION, CORE_REVISION, SCHEMA_VERSION,
)
from app.b2_genesis_authorization import (
    prepare_genesis_approval_request_commitment, genesis_authorization_context,
    GenesisAuthorizationEvidence, GenesisAuthorizationVerifier, VerifiedGenesisAuthorization,
    FOUNDATION_CHECKPOINT, NON_PRODUCTION,
)
from app.r1_scoped_activation_core import (
    ScopedV2PostgresCore, encode_opening, decode_opening, verify_opening,
)
from .b2_activation_access import FixedAccess, AccessPolicy

MIGRATION_CHECKPOINT = "19f4943b68bc0f8559c1c9a91db03340431282bd"
GENESIS_AUTHORIZATION_CHECKPOINT = "ff1fc37e6028aeef56ed7c41d5d2237cc59837b4"
PREAPPROVAL_CHECKPOINT = "5d00af4a692787137d8cf5b8fa30ca39a655470e"
BACKUP_GENERATION = "backup-post-real-binding-20261004T144423Z-baba5668"
SIGNER_KEY_ID = "c8846c02c0456182cb36d555b93d185172db8bcc01e699c9e3861cb9f5fc91ca"
FIRST_OWNER_CHECKPOINT = "8def73ca38252fac90f4b2c29b58651ca7e7cafe"
FIRST_OWNER_DECISION_SHA256 = "aed2ad38011e0104048710432a400ab183b889efccdc543a428d65253b0660fd"
CONFIRM = {
    "control_migration": "APPLY_ONLY_B2_004_TO_QINGYU_CONTROL",
    "core_migration": "APPLY_ONLY_B2_005_TO_QINGYU_PROD",
    "authority": "CREATE_EXACT_QINGYU_PRODUCTION_AUTHORITY",
    "smi": "PERSIST_EXACT_QINGYU_PRODUCTION_SIGNED_MIGRATION_INTENT",
    "genesis": "IRREVERSIBLY_EXECUTE_EXACT_QINGYU_SCOPED_V2_NEW_GENESIS",
}
EXPECTED_COLUMNS = {
    "activation_authorities": (("authority_reference","text"),("environment","text"),("target_reference","text"),("admission_reference","text"),("record_wire","bytea"),("record_hash","text"),("persisted_at","timestamp with time zone")),
    "activation_smis": (("intent_id","text"),("authority_reference","text"),("authority_hash","text"),("record_wire","bytea"),("record_hash","text"),("persisted_at","timestamp with time zone")),
    "identity": (("singleton","smallint"),("identity_id","uuid"),("continuity_id","uuid"),("genesis_operation_id","uuid"),("record_wire","bytea"),("record_hash","text")),
    "genesis": (("singleton","smallint"),("operation_id","uuid"),("identity_hash","text"),("proof_wire","bytea"),("proof_hash","text"),("persisted_at","timestamp with time zone")),
    "lifecycle": (("singleton","smallint"),("genesis_operation_id","uuid"),("state","text"),("checkpoint_wire","bytea"),("checkpoint_hash","text")),
}
EXPECTED_CONSTRAINT_COUNTS = {
    "activation_authorities":{"p":1,"u":3,"f":1,"c":1},
    "activation_smis":{"p":1,"u":1,"f":1,"c":1},
    "identity":{"p":1,"u":4,"c":2},
    "genesis":{"p":1,"u":1,"f":2,"c":2},
    "lifecycle":{"p":1,"f":1,"c":3},
}
EXPECTED_CONSTRAINTS = {
    "activation_authorities": ("PRIMARY KEY (authority_reference)","UNIQUE (record_hash)","UNIQUE (environment, target_reference)","UNIQUE (authority_reference, record_hash)","FOREIGN KEY (admission_reference) REFERENCES governance.production_signer_admission_trust_bindings(admission_reference)","CHECK (record_hash ~ '^[0-9a-f]{64}$')"),
    "activation_smis": ("PRIMARY KEY (intent_id)","UNIQUE (record_hash)","FOREIGN KEY (authority_reference, authority_hash) REFERENCES governance.activation_authorities(authority_reference, record_hash)","CHECK (record_hash ~ '^[0-9a-f]{64}$')"),
    "identity": ("PRIMARY KEY (singleton)","UNIQUE (identity_id)","UNIQUE (continuity_id)","UNIQUE (genesis_operation_id)","UNIQUE (record_hash)","CHECK (singleton = 1)","CHECK (record_hash ~ '^[0-9a-f]{64}$')"),
    "genesis": ("PRIMARY KEY (singleton)","UNIQUE (operation_id)","FOREIGN KEY (operation_id) REFERENCES r1_core_v2.identity(genesis_operation_id)","FOREIGN KEY (identity_hash) REFERENCES r1_core_v2.identity(record_hash)","CHECK (singleton = 1)","CHECK (proof_hash ~ '^[0-9a-f]{64}$')"),
    "lifecycle": ("PRIMARY KEY (singleton)","FOREIGN KEY (genesis_operation_id) REFERENCES r1_core_v2.genesis(operation_id)","CHECK (singleton = 1)","CHECK (state = 'GENESIS_DURABLE')","CHECK (checkpoint_hash ~ '^[0-9a-f]{64}$')"),
}


def fail(code):
    raise CoreError("B2_OPS_" + code)


def prepared_body(request,expected_type,fields):
    if type(request) is not expected_type or type(request.wire) is not bytes or len(request.wire)>1_048_576:
        fail("PREPARED_REQUEST_INVALID")
    try: body=decode(request.wire)
    except (ValueError,TypeError,UnicodeError): fail("PREPARED_REQUEST_INVALID")
    if type(body) is not dict or set(body)!=set(fields): fail("PREPARED_REQUEST_FIELDS")
    return body


@dataclass(frozen=True)
class PreparedAuthority:
    wire: bytes


@dataclass(frozen=True)
class PreparedSMI:
    wire: bytes


@dataclass(frozen=True)
class PreparedGenesis:
    wire: bytes


@dataclass(frozen=True)
class OwnerRequestPackage:
    wire: bytes


@dataclass(frozen=True)
class RecoveryBoundary:
    """Protected recovery-policy installation, never a request flag.

    Historical Binding-bearing recovery is not a fresh activation backup. Real
    enrollment must independently verify and install stage/request-specific
    anchors after reviewing each new durable stage. Missing anchors fail closed.
    Synthetic installation can carry clearly labelled test-only anchors.
    """
    classification: str
    binding_hash: str
    historical_generation: str
    anchors: tuple  # (stage, exact prepared-request hash, verified anchor reference)

    def verify(self,stage,request_hash):
        if self.classification==REAL_PRODUCTION and self.historical_generation!=BACKUP_GENERATION:
            fail("RECOVERY_HISTORICAL_ANCHOR_MISMATCH")
        found=[ref for s,h,ref in self.anchors if s==stage and h==request_hash]
        if len(found)!=1: fail("FRESH_RECOVERY_ANCHOR_REQUIRED")
        if self.classification==SYNTHETIC_TEST and not found[0].startswith("NON_PRODUCTION:"):
            fail("SYNTHETIC_RECOVERY_REQUIRED")
        return {"state":"RECOVERY_READY","reference":found[0]}


@dataclass(frozen=True)
class ExecutionJournal:
    """Non-secret operational transition, not Core or governance authority.

    A protected deployment supplies the path. Real path is fixed; synthetic
    files live in a clearly labelled task-owned temporary directory. Corrupt,
    conflicting or incomplete journal writes stop before the activation send.
    This never rolls back or repairs a durable Authority/SMI/GENESIS record.
    """
    classification: str
    path: Path

    def begin_authority(self,request_hash):
        if self.classification==REAL_PRODUCTION:
            if str(self.path)!="/var/lib/qingyu/activation/operational-state.json": fail("JOURNAL_PATH_MISMATCH")
        elif self.classification!=SYNTHETIC_TEST or "NON_PRODUCTION" not in self.path.parts:
            fail("SYNTHETIC_JOURNAL_REQUIRED")
        if self.path.is_symlink() or self.path.parent.is_symlink(): fail("JOURNAL_STORAGE_UNTRUSTED")
        expected={"classification":self.classification,"state":"ACTIVATION_EXECUTING",
                  "authority_request_hash":request_hash,"implementation_checkpoint":PREAPPROVAL_CHECKPOINT}
        if self.path.exists():
            try: found=json.loads(self.path.read_text(encoding="utf-8"))
            except (ValueError,OSError): fail("JOURNAL_RECONCILIATION_REQUIRED")
            if found!=expected: fail("JOURNAL_CONFLICT")
            return
        try:
            with self.path.open("x",encoding="utf-8") as stream:
                stream.write(json.dumps(expected,sort_keys=True)+"\n");stream.flush();os.fsync(stream.fileno())
        except OSError: fail("JOURNAL_RECONCILIATION_REQUIRED")


@dataclass(frozen=True)
class OperationalPolicy:
    """Protected installation, NOT serialized operational request data.

    Real installation must come from reviewed deployment/governance sources.
    This module installs no production Owner pin and reads no credential source.
    Engines/stores come only from the existing approved credential composition;
    the public execution methods never accept an engine, URL, file or provider.
    """
    access: AccessPolicy
    target_wire: bytes
    activation_approval_wire: bytes
    intent_payload_hash: str
    intent_wire: bytes
    trust_hash: str
    admission_hash: str
    binding_hash: str
    signer_key_id: str
    foundation: str
    genesis_amendment: str
    migration_amendment: str
    preapproval_amendment: str
    first_owner_decision_wire: bytes | None = None

    def __post_init__(self):
        if type(self.access) is not AccessPolicy: fail("PROTECTED_COMPOSITION_REQUIRED")
        if self.access.classification == REAL_PRODUCTION:
            if (self.foundation,self.genesis_amendment,self.migration_amendment,self.preapproval_amendment) != (
                    FOUNDATION_CHECKPOINT,GENESIS_AUTHORIZATION_CHECKPOINT,MIGRATION_CHECKPOINT,PREAPPROVAL_CHECKPOINT):
                fail("FROZEN_LINEAGE_MISMATCH")
            target=decode(self.target_wire)
            # Runtime classification and the historical source environment name
            # are distinct frozen fields; neither is rewritten to fit the other.
            if target.get("environment_identity")!="qingyu-production-primary" or target.get("host_reference")!="qingyu-prod-local-01" or target.get("database_reference")!="qingyu_prod" or target.get("target_reference")!="prod-target-ref-001" or target.get("signer_trust_reference")!="qingyu-prod-trust-01" or self.signer_key_id!=SIGNER_KEY_ID:
                fail("TARGET_OR_SIGNER_MISMATCH")
            if type(self.first_owner_decision_wire) is not bytes or sha(self.first_owner_decision_wire)!=FIRST_OWNER_DECISION_SHA256:
                fail("FROZEN_FIRST_OWNER_DECISION_REQUIRED")
            decision=json.loads(self.first_owner_decision_wire)
            if decision["owner_decision"]!="APPROVE_B2_ACTIVATION": fail("FROZEN_FIRST_OWNER_DECISION_REQUIRED")
            identity=decision["canonical_identity"]
            if (self.trust_hash,self.admission_hash,self.binding_hash)!=(identity["trust_hash"],identity["admission_hash"],identity["binding_hash"]):
                fail("FIRST_OWNER_SOURCE_SCOPE_MISMATCH")
        elif not all(x.startswith("NON_PRODUCTION:") for x in (
                self.foundation,self.genesis_amendment,self.migration_amendment,self.preapproval_amendment)):
            fail("SYNTHETIC_LINEAGE_REQUIRED")


def capture_then_parse(completed, capture_sink):
    """Only public executor outputs belong here, NEVER credential subprocesses.

    Raw bytes and exit code are captured synchronously even on nonzero exit or
    malformed JSON. Sink failure stops parsing; it cannot turn a send into retry.
    """
    raw={"stdout_hex":completed.stdout.hex(),"stderr_hex":completed.stderr.hex(),
         "exit_code":completed.returncode,"RAW_CAPTURE_BEFORE_PARSE":True}
    capture_sink(raw)
    if completed.returncode: fail("SUBPROCESS_RECONCILIATION_REQUIRED")
    try:
        parsed=json.loads(completed.stdout.decode("utf-8",errors="strict"))
    except (ValueError,UnicodeError):
        fail("SUBPROCESS_RECONCILIATION_REQUIRED")
    if type(parsed) is not dict: fail("SUBPROCESS_RECONCILIATION_REQUIRED")
    return parsed


class MigrationExecutor:
    """One fixed canonical bundle. No migration/SQL/target execution argument."""
    def __init__(self, target, access, recovery):
        if type(target) is not ProtectedMigrationTarget or type(access) is not FixedAccess:
            fail("PROTECTED_COMPOSITION_REQUIRED")
        self.target,self.access,self.recovery=target,access,recovery
        p=access.policy
        if target.database!=p.database(target.kind) or target.verifier.classification!=p.classification:
            fail("TARGET_MISMATCH")
        if p.classification==REAL_PRODUCTION and target.verifier.amendment_checkpoint!=MIGRATION_CHECKPOINT:
            fail("FROZEN_LINEAGE_MISMATCH")

    def prepare(self):
        return self.target.prepared_plan()

    def preflight(self, plan, authorization):
        if type(plan) is not PreparedMigrationPlan or plan.wire!=self.prepare().wire:
            fail("MIGRATION_PLAN_MISMATCH")
        if type(authorization) is not VerifiedProductionMigrationAuthorization:
            fail("MIGRATION_CAPABILITY_REQUIRED")
        self.target.verifier.revalidate(authorization,plan)
        self.access.endpoint(self.target.engine,self.target.kind)
        with self.target.engine.connect() as c:
            kind=self.target.kind
            self.access.identity(c,kind+"_migrator",kind,owner_context=True)
            role=c.execute(text("SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls FROM pg_roles WHERE rolname=session_user")).one()
            if any(role): fail("MIGRATOR_PRIVILEGE_MISMATCH")
            membership=c.execute(text("SELECT pg_get_userbyid(roleid),admin_option,inherit_option,set_option FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=session_user)")).all()
            if [tuple(x) for x in membership]!=[(self.access.policy.owner(kind),False,False,True)]: fail("MIGRATOR_MEMBERSHIP_MISMATCH")
            owner_flags=c.execute(text("SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls FROM pg_roles WHERE rolname=current_user")).one()
            if any(owner_flags): fail("MIGRATION_OWNER_PRIVILEGE_MISMATCH")
            schema="governance" if kind=="control" else "r1_core_v2"
            existing=c.execute(text("SELECT to_regnamespace(:s)"),{"s":schema}).scalar_one()
            if existing:
                owner=c.execute(text("SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname=:s"),{"s":schema}).scalar_one()
                if owner!=self.access.policy.owner(kind): fail("MIGRATION_OWNER_MISMATCH")
            elif not c.execute(text("SELECT has_database_privilege(current_database(),'CREATE')")).scalar_one():
                fail("MIGRATION_ACL_MISMATCH")
        self.recovery.verify("schema",plan.plan_hash)
        state=self.reconcile()
        if state not in {"NOT_APPLIED","APPLIED_EXACT"}: fail("MIGRATION_RECONCILIATION_REQUIRED")
        return state

    def execute(self, plan, authorization, *, confirmation):
        if confirmation!=CONFIRM[self.target.kind+"_migration"]: fail("MIGRATION_CONFIRMATION_REQUIRED")
        state=self.preflight(plan,authorization)
        if state=="APPLIED_EXACT": return self.result("APPLIED_EXACT",False,False)
        try:
            apply_activation_migration(self.target,database=self.target.database,kind=self.target.kind,authorization=authorization)
        except DBAPIError:
            return self.result("UNKNOWN_NOT_SAFELY_CLASSIFIABLE",True,True)
        except CoreError as ex:
            if "DATABASE" in str(ex) or "RECONCILIATION" in str(ex):
                return self.result("UNKNOWN_NOT_SAFELY_CLASSIFIABLE",True,True)
            raise
        state=self.reconcile()
        return self.result(state,True,state!="APPLIED_EXACT")

    def result(self,state,attempted,uncertain):
        return {"operation":self.target.kind+"_migration","target":self.target.database,
                "environment":self.target.environment,"actor":self.access.policy.role(self.target.kind+"_migrator"),
                "prepared_request_hash":self.prepare().plan_hash,"authorization_state":"GOVERNANCE_REVALIDATED",
                "confirmation_state":"EXACT","preflight_state":"OPERATION_READY","mutation_attempted":attempted,
                "readback_state":state,
                "durable_state":state,"reconciliation_required":uncertain,
                "next_gate":"READ_ONLY_RECONCILIATION" if uncertain else "SCHEMA_READY_ONLY"}

    def probe(self):
        return {"operation":self.target.kind+"_migration","state":"CONFIG_VALID",
                "schema_state":self.reconcile(),"governance_state":"NOT_CHECKED",
                "mutation_attempted":False}

    def reconcile(self):
        kind=self.target.kind; schema="governance" if kind=="control" else "r1_core_v2"
        revision=CONTROL_REVISION if kind=="control" else CORE_REVISION
        tables=("activation_authorities","activation_smis") if kind=="control" else ("identity","genesis","lifecycle")
        try:
            self.access.endpoint(self.target.engine,kind)
            with self.target.engine.connect() as c:
                self.access.identity(c,kind+"_migrator",kind,owner_context=True)
                ledger=c.execute(text("SELECT to_regclass(:t)"),{"t":schema+".activation_migrations"}).scalar_one()
                present=[bool(c.execute(text("SELECT to_regclass(:t)"),{"t":schema+"."+n}).scalar_one()) for n in tables]
                if ledger is None: return "CONFLICTING" if any(present) else "NOT_APPLIED"
                versions=c.execute(text("SELECT revision,version FROM "+schema+".activation_migrations")).all()
                if not versions: return "CONFLICTING" if any(present) else "NOT_APPLIED"
                if [tuple(x) for x in versions]!=[(revision,SCHEMA_VERSION)] or not all(present): return "CONFLICTING"
                for table in tables:
                    triggers=c.execute(text("SELECT t.tgname,t.tgenabled,t.tgtype,p.proname,n.nspname FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace WHERE tgrelid=to_regclass(:t) AND NOT tgisinternal"),{"t":schema+"."+table}).all()
                    if sorted(tuple(x) for x in triggers)!=[("activation_immutable","O",27,"activation_immutable",schema),("activation_no_truncate","O",34,"activation_immutable",schema)]: return "CONFLICTING"
                    columns=c.execute(text("SELECT attname,format_type(atttypid,atttypmod),attnotnull FROM pg_attribute WHERE attrelid=to_regclass(:t) AND attnum>0 AND NOT attisdropped ORDER BY attnum"),{"t":schema+"."+table}).all()
                    if [tuple(x) for x in columns]!=[(n,t,True) for n,t in EXPECTED_COLUMNS[table]]: return "CONFLICTING"
                    counts=dict(c.execute(text("SELECT contype,count(*) FROM pg_constraint WHERE conrelid=to_regclass(:t) GROUP BY contype"),{"t":schema+"."+table}).all())
                    if counts!=EXPECTED_CONSTRAINT_COUNTS[table]: return "CONFLICTING"
                    definitions=c.execute(text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=to_regclass(:t)"),{"t":schema+"."+table}).scalars().all()
                    def normalize(value):
                        return ''.join(value.replace('::text','').split()).replace('(','').replace(')','')
                    if sorted(map(normalize,definitions))!=sorted(map(normalize,EXPECTED_CONSTRAINTS[table])): return "CONFLICTING"
                    owner=c.execute(text("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid=to_regclass(:t)"),{"t":schema+"."+table}).scalar_one()
                    if owner!=self.access.policy.owner(kind): return "CONFLICTING"
                function=c.execute(text("SELECT prosrc,prosecdef,proconfig FROM pg_proc WHERE oid=to_regprocedure(:p)"),{"p":schema+".activation_immutable()"}).one()
                normalized=" ".join(function[0].split())
                if normalized!="BEGIN RAISE EXCEPTION 'immutable activation history' USING ERRCODE='55000'; END" or function[1] or function[2]!=["search_path=pg_catalog"]:
                    return "CONFLICTING"
                return "APPLIED_EXACT"
        except (DBAPIError,CoreError):
            return "UNKNOWN_NOT_SAFELY_CLASSIFIABLE"


class ActivationOperations:
    """Protected stores/providers are fixed once; requests cannot replace them."""
    def __init__(self, policy, *, authority_store, smi_store, core, signer, recovery, journal):
        if type(policy) is not OperationalPolicy or type(core) is not ScopedV2PostgresCore:
            fail("PROTECTED_COMPOSITION_REQUIRED")
        self.policy=policy; self.access=FixedAccess(policy.access)
        self.authority,self.smi,self.core=authority_store,smi_store,core
        self.signer,self.recovery=signer,recovery
        if type(journal) is not ExecutionJournal or journal.classification!=policy.access.classification:
            fail("PROTECTED_JOURNAL_REQUIRED")
        self.journal=journal
        if type(recovery) is not RecoveryBoundary or recovery.classification!=policy.access.classification or recovery.binding_hash!=policy.binding_hash:
            fail("PROTECTED_RECOVERY_REQUIRED")
        expected_mode=AuthorityEnvironmentMode.REAL_PRODUCTION if policy.access.classification==REAL_PRODUCTION else AuthorityEnvironmentMode.SYNTHETIC_PRODUCTION_TEST
        if core.mode!=expected_mode or core.route!="SCOPED_V2_POSTGRES" or core.database!=policy.access.core_database:
            fail("CORE_TARGET_OR_ROUTE_MISMATCH")
        for store in (authority_store,smi_store,core.control):
            if store.database!=policy.access.control_database or c2(store.target.model_dump(mode="json"))!=policy.target_wire:
                fail("CONTROL_TARGET_MISMATCH")
        self.approval=OwnerApproval.model_validate(decode(policy.activation_approval_wire))
        self._intent(policy.intent_wire)

    def _configuration(self):
        expected=AuthorityEnvironmentMode.REAL_PRODUCTION if self.policy.access.classification==REAL_PRODUCTION else AuthorityEnvironmentMode.SYNTHETIC_PRODUCTION_TEST
        if self.core.mode!=expected or self.core.route!="SCOPED_V2_POSTGRES" or self.core.database!=self.policy.access.core_database:
            fail("CORE_TARGET_OR_ROUTE_MISMATCH")
        for store,actor in ((self.authority,"authority"),(self.smi,"smi"),(self.core.control,"reader")):
            if store.database!=self.policy.access.control_database or c2(store.target.model_dump(mode="json"))!=self.policy.target_wire:
                fail("CONTROL_TARGET_MISMATCH")
            self.access.endpoint(store.engine,"control")
            if store.engine.url.username!=self.policy.access.role(actor): fail("SESSION_ACTOR_OR_TARGET_MISMATCH")
            for source in (store.sources.trust_store,store.sources.admission_store,store.sources.binding_store):
                self.access.endpoint(source.engine,"control")
        self.access.endpoint(self.core.engine,"core")
        if self.core.engine.url.username!=self.policy.access.role("genesis"): fail("SESSION_ACTOR_OR_TARGET_MISMATCH")

    def _sources(self):
        self._configuration()
        source=self.authority.sources.load(self.authority.target)
        from app.b2_signer_trust import TrustRecord,ProductionSignerAdmissionRecord
        trust=TrustRecord.model_validate(source["trust"])
        admission=ProductionSignerAdmissionRecord.model_validate(source["admission"])
        allowed=(SignerProviderClassification.PRODUCTION_ELIGIBLE,) if self.policy.access.classification==REAL_PRODUCTION else (SignerProviderClassification.TEST_ONLY,SignerProviderClassification.SYNTHETIC_PRODUCTION_TEST_ONLY)
        if trust.provider_classification not in allowed: fail("SIGNER_CLASSIFICATION_MISMATCH")
        from app.b2_signer_trust import ProductionSignerAdmissionTrustBinding
        if (_trust_record_hash(trust),_admission_record_hash(admission),ProductionSignerAdmissionTrustBinding.model_validate(source["binding"]).binding_hash,trust.key_id)!=(
                self.policy.trust_hash,self.policy.admission_hash,self.policy.binding_hash,self.policy.signer_key_id):
            fail("SOURCE_PIN_MISMATCH")
        return source

    def _intent(self, wire):
        intent=SignedMigrationIntent.model_validate(decode(wire))
        if intent.canonical_payload_hash!=self.policy.intent_payload_hash: fail("INTENT_SUBSTITUTION")
        if intent.signer_key_id!=self.policy.signer_key_id: fail("SIGNER_KEY_MISMATCH")
        validate_owner_approval(approval=self.approval,target=self.authority.target,intent=intent)
        if self.approval.approval_state!="OWNER_APPROVED" or self.approval.approval_reference!=intent.owner_approval_reference:
            fail("ACTIVATION_OWNER_APPROVAL_MISMATCH")
        return intent

    def prepare_authority(self, *, created_at, provenance_record, intent):
        # The first activation approval governs the intent BEFORE Authority write.
        self._intent(c2(intent.model_dump(mode="json"))); self._sources()
        candidate=self.authority.preview_authority(authority_reference=self.authority.target.authority_reference,
            created_at=created_at,provenance_record=provenance_record)
        return PreparedAuthority(candidate.wire)

    def authority_preflight(self, request):
        if type(request) is not PreparedAuthority: fail("PREPARED_AUTHORITY_REQUIRED")
        body=prepared_body(request,PreparedAuthority,("schema_version","authority_reference","target","sources","v2_configuration","created_at","provenance"))
        self._intent(self.policy.intent_wire)
        self._sources(); self.access.runtime_preflight(self.authority.engine,"authority","control")
        candidate=self.authority.preview_authority(authority_reference=body["authority_reference"],
            created_at=datetime.fromisoformat(body["created_at"]),provenance_record=body["provenance"])
        if candidate.wire!=request.wire: fail("AUTHORITY_REQUEST_SUBSTITUTION")
        state=self.reconcile_authority(request)
        if state not in {"AUTHORITY_ABSENT","AUTHORITY_DURABLE_EXACT"}: fail("AUTHORITY_CONFLICT")
        self.recovery.verify("authority",sha(request.wire))
        return state

    def execute_authority(self, request, *, confirmation):
        if confirmation!=CONFIRM["authority"]: fail("AUTHORITY_CONFIRMATION_REQUIRED")
        state=self.authority_preflight(request)
        body=decode(request.wire)
        if state=="AUTHORITY_DURABLE_EXACT":
            result=self._result("authority",request,state,False,False)
            result["canonical_outcome"]="EXACT_REPLAY";result["transition"]=None
            return result
        # Durable operational metadata precedes the first activation-domain send.
        self.journal.begin_authority(sha(request.wire))
        return self._send("authority",request,lambda:self.authority.create_authority(
            authority_reference=body["authority_reference"],created_at=datetime.fromisoformat(body["created_at"]),
            provenance_record=body["provenance"]),lambda:self.reconcile_authority(request))

    def reconcile_authority(self, request):
        if type(request) is not PreparedAuthority: fail("PREPARED_AUTHORITY_REQUIRED")
        try:
            self._configuration()
            row=self.authority.read_authority(self.authority.target.authority_reference)
            if row is None: return "AUTHORITY_ABSENT"
            return "AUTHORITY_DURABLE_EXACT" if row.wire==request.wire else "AUTHORITY_DURABLE_CONFLICTING"
        except (DBAPIError,CoreError): return "AUTHORITY_STATE_UNKNOWN"
        except (ContractError,ValidationError,ValueError,KeyError,TypeError): return "AUTHORITY_DURABLE_CONFLICTING"

    def prepare_smi(self, intent, authority_request):
        if type(authority_request) is not PreparedAuthority: fail("PREPARED_AUTHORITY_REQUIRED")
        self._intent(c2(intent.model_dump(mode="json")))
        return PreparedSMI(c2({"intent":intent.model_dump(mode="json"),
            "authority_hash":activation_hash("authority",authority_request.wire),
            "authority_reference":self.authority.target.authority_reference}))

    def _smi_intent(self,request):
        body=prepared_body(request,PreparedSMI,("intent","authority_hash","authority_reference"))
        if set(body)!={"intent","authority_hash","authority_reference"} or body["authority_reference"]!=self.authority.target.authority_reference:
            fail("SMI_REQUEST_FIELDS")
        return self._intent(c2(body["intent"]))

    def sign_smi(self, request, *, confirmation):
        # Signing has separate explicit operational intent; probes never call it.
        if confirmation!=CONFIRM["smi"]: fail("SMI_CONFIRMATION_REQUIRED")
        if type(request) is not PreparedSMI: fail("PREPARED_SMI_REQUIRED")
        intent=self._smi_intent(request); self._sources()
        authority=self.smi.read_authority(self.authority.target.authority_reference)
        if authority is None or authority.record_hash!=decode(request.wire)["authority_hash"]: fail("SMI_AUTHORITY_SUBSTITUTION")
        if self.signer.key_id!=self.policy.signer_key_id: fail("SIGNER_KEY_MISMATCH")
        allowed=(SignerProviderClassification.PRODUCTION_ELIGIBLE,) if self.policy.access.classification==REAL_PRODUCTION else (SignerProviderClassification.TEST_ONLY,SignerProviderClassification.SYNTHETIC_PRODUCTION_TEST_ONLY)
        if self.signer.classification not in allowed: fail("SIGNER_CLASSIFICATION_MISMATCH")
        source=self._sources()["trust"]
        if self.signer.provider_reference!=source["provider_reference"] or self.signer.backend_type!=source["provider_backend_type"]: fail("SIGNER_PROVIDER_MISMATCH")
        from app.b2_signer_trust import TrustRecord
        ensure_production_eligible(TrustRecord.model_validate(source),mode=self.core.mode,
            admission_store=self.authority.sources.admission_store,signer_provider=self.signer)
        signed=intent.model_dump(mode="json")
        signed["signature_metadata"]["signature"]=sign_smi_payload(self.signer,intent.canonical_payload())
        result=PreparedSMI(c2({**decode(request.wire),"intent":signed})); self.verify_smi(result,now=None)
        return result

    def verify_smi(self,request,*,now):
        if type(request) is not PreparedSMI: fail("PREPARED_SMI_REQUIRED")
        intent=self._smi_intent(request)
        authority=self.smi.read_authority(self.authority.target.authority_reference)
        if authority is None: fail("DURABLE_AUTHORITY_REQUIRED")
        if authority.record_hash!=decode(request.wire)["authority_hash"]: fail("SMI_AUTHORITY_SUBSTITUTION")
        self.smi._verify_intent(intent,authority,now=now)
        return intent

    def smi_preflight(self,request,*,now):
        self.access.runtime_preflight(self.smi.engine,"smi","control")
        self._sources()
        state=self.reconcile_smi(request)
        intent=self.verify_smi(request,now=None if state=="SMI_DURABLE_EXACT" else now)
        if state not in {"SMI_ABSENT","SMI_DURABLE_EXACT"}: fail("SMI_CONFLICT")
        self.recovery.verify("smi",sha(request.wire))
        return intent

    def execute_smi(self,request,*,now,confirmation):
        if confirmation!=CONFIRM["smi"]: fail("SMI_CONFIRMATION_REQUIRED")
        intent=self.smi_preflight(request,now=now)
        return self._send("smi",request,lambda:self.smi.persist_smi(intent,
            authority_reference=self.authority.target.authority_reference,now=now),lambda:self.reconcile_smi(request))

    def reconcile_smi(self,request):
        if type(request) is not PreparedSMI: fail("PREPARED_SMI_REQUIRED")
        try:
            self._configuration()
            intent=self._smi_intent(request); row=self.smi.read_smi(intent.intent_id)
            if row is None: return "SMI_ABSENT"
            return "SMI_DURABLE_EXACT" if row.payload["intent"]==decode(request.wire)["intent"] and row.payload["authority_hash"]==decode(request.wire)["authority_hash"] else "SMI_DURABLE_CONFLICTING"
        except (DBAPIError,CoreError): return "SMI_STATE_UNKNOWN"
        except (ContractError,ValidationError,ValueError,KeyError,TypeError): return "SMI_DURABLE_CONFLICTING"

    def prepare_genesis(self, *, intent_id, opening):
        if intent_id!=self._intent(self.policy.intent_wire).intent_id: fail("INTENT_SUBSTITUTION")
        verify_opening(opening,self.core.configuration)
        return PreparedGenesis(c2({"authority_reference":self.authority.target.authority_reference,
            "intent_id":intent_id,"opening_wire":encode_opening(opening).hex(),
            "activation_approval":decode(self.policy.activation_approval_wire)}))

    def _genesis_args(self,request):
        if type(request) is not PreparedGenesis: fail("PREPARED_GENESIS_REQUIRED")
        body=prepared_body(request,PreparedGenesis,("authority_reference","intent_id","opening_wire","activation_approval"))
        if set(body)!={"authority_reference","intent_id","opening_wire","activation_approval"}: fail("GENESIS_REQUEST_FIELDS")
        if body["authority_reference"]!=self.authority.target.authority_reference or c2(body["activation_approval"])!=self.policy.activation_approval_wire:
            fail("GENESIS_REQUEST_SUBSTITUTION")
        smi=self.core.control.read_smi(body["intent_id"])
        if smi is None: fail("DURABLE_SMI_REQUIRED")
        self._intent(c2(smi.payload["intent"]))
        return {"authority_reference":body["authority_reference"],"intent_id":body["intent_id"],
            "opening":decode_opening(bytes.fromhex(body["opening_wire"])),"owner_approval":self.approval}

    def owner_request_package(self,request):
        args=self._genesis_args(request); self._sources()
        self.access.runtime_preflight(self.core.engine,"genesis","core")
        self.core.read_pre_genesis_state()
        kw={"synthetic_foundation_checkpoint":self.policy.foundation} if self.policy.access.classification==SYNTHETIC_TEST else {}
        commitment=prepare_genesis_approval_request_commitment(self.core,
            authority_reference=args["authority_reference"],intent_id=args["intent_id"],opening=args["opening"],activation_approval=self.approval,**kw)
        return OwnerRequestPackage(c2({"label":"NOT AUTHORIZATION; NOT EXECUTION APPROVAL",
            "decision_required":"APPROVE_REAL_V2_NEW_GENESIS" if self.policy.access.classification==REAL_PRODUCTION else "APPROVE_SYNTHETIC_V2_NEW_GENESIS",
            "context":decode(commitment.wire),"preapproval_amendment":self.policy.preapproval_amendment,
            "genesis_authorization_amendment":self.policy.genesis_amendment,
            "future_checkpoint_and_trusted_pin_installation":"REQUIRED_LATER"}))

    def verify_owner(self,request,evidence):
        if type(evidence) is not GenesisAuthorizationEvidence: fail("GENESIS_OWNER_EVIDENCE_REQUIRED")
        if type(self.core.genesis_authorization_verifier) is not GenesisAuthorizationVerifier: fail("PROTECTED_OWNER_POLICY_REQUIRED")
        if self.core.genesis_authorization_verifier.foundation_checkpoint!=self.policy.foundation: fail("FROZEN_LINEAGE_MISMATCH")
        args=self._genesis_args(request)
        context=genesis_authorization_context(self.core,**args)
        return self.core.genesis_authorization_verifier.verify(evidence,context)

    def genesis_preflight(self,request,authorization,*,now):
        if type(authorization) is not VerifiedGenesisAuthorization: fail("GENESIS_FINAL_OWNER_CONFIRMATION_REQUIRED")
        if type(self.core.genesis_authorization_verifier) is not GenesisAuthorizationVerifier or self.core.genesis_authorization_verifier.foundation_checkpoint!=self.policy.foundation:
            fail("FROZEN_LINEAGE_MISMATCH")
        self.access.runtime_preflight(self.core.engine,"genesis","core"); self._sources()
        self.access.runtime_preflight(self.core.control.engine,"reader","control")
        args=self._genesis_args(request)
        self.core._verify_genesis_authorization(authorization,**args)
        state=self.core.read_genesis_state()
        self.recovery.verify("genesis",sha(request.wire))
        if state["status"]=="PRE_GENESIS":
            self.core.final_owner_confirmation_gate(**args,now=now,authorization=authorization)
        elif self.reconcile_genesis(request)!="GENESIS_DURABLE_EXACT": fail("GENESIS_CONFLICT")
        return args

    def execute_genesis(self,request,authorization,*,now,confirmation):
        if confirmation!=CONFIRM["genesis"]: fail("GENESIS_CONFIRMATION_REQUIRED")
        args=self.genesis_preflight(request,authorization,now=now)
        return self._send("genesis",request,lambda:self.core.execute_new_genesis(**args,now=now,authorization=authorization),
            lambda:self.reconcile_genesis(request))

    def reconcile_genesis(self,request):
        try:
            self._configuration()
            args=self._genesis_args(request)
            kw={"synthetic_foundation_checkpoint":self.policy.foundation} if self.policy.access.classification==SYNTHETIC_TEST else {}
            commitment=prepare_genesis_approval_request_commitment(self.core,
                authority_reference=args["authority_reference"],intent_id=args["intent_id"],opening=args["opening"],activation_approval=self.approval,**kw)
            value=self.core.reconcile_new_genesis(commitment.genesis_request_hash)
            return {"ABSENT":"PRE_GENESIS","EXACT":"GENESIS_DURABLE_EXACT","CONFLICT":"GENESIS_DURABLE_CONFLICTING_STATE"}[value]
        except (DBAPIError,CoreError): return "GENESIS_STATE_UNKNOWN"
        except (ContractError,ValidationError,ValueError,KeyError,TypeError): return "GENESIS_DURABLE_CONFLICTING_STATE"

    def partial_state(self,authority_request,smi_request,genesis_request=None):
        try: self._configuration()
        except CoreError: return "UNKNOWN_STATE"
        a=self.reconcile_authority(authority_request); s=self.reconcile_smi(smi_request)
        try: core_state=self.core.genesis_durable_predicate()["status"]
        except (DBAPIError,CoreError): return "UNKNOWN_STATE"
        if core_state=="GENESIS_DURABLE_CONFLICTING_STATE": return "CONFLICTING_STATE"
        if "UNKNOWN" in a or "UNKNOWN" in s: return "UNKNOWN_STATE"
        if "CONFLICTING" in a or "CONFLICTING" in s or (a=="AUTHORITY_ABSENT" and s!="SMI_ABSENT"): return "CONFLICTING_STATE"
        if core_state!="PRE_GENESIS" and (a=="AUTHORITY_ABSENT" or s=="SMI_ABSENT"): return "CONFLICTING_STATE"
        if a=="AUTHORITY_ABSENT": return "OWNER_APPROVED_AUTHORITY_ABSENT"
        if s=="SMI_ABSENT": return "AUTHORITY_DURABLE_SMI_ABSENT"
        if genesis_request is None: return "AUTHORITY_AND_SMI_DURABLE_PRE_GENESIS" if core_state=="PRE_GENESIS" else "UNKNOWN_STATE"
        g=self.reconcile_genesis(genesis_request)
        return {"PRE_GENESIS":"AUTHORITY_AND_SMI_DURABLE_PRE_GENESIS","GENESIS_DURABLE_EXACT":"GENESIS_DURABLE_EXACT",
                "GENESIS_DURABLE_CONFLICTING_STATE":"CONFLICTING_STATE","GENESIS_STATE_UNKNOWN":"UNKNOWN_STATE"}[g]

    def pre_genesis_coordinator(self,authority_request,smi_request,genesis_request,*,now,authority_confirmation,smi_confirmation):
        # Infrastructure is a separate explicit phase: this coordinator never
        # chooses migration consent, creates Owner approvals, or calls GENESIS.
        if authority_confirmation!=CONFIRM["authority"] or smi_confirmation!=CONFIRM["smi"]: fail("COORDINATOR_CONFIRMATION_REQUIRED")
        self.access.runtime_preflight(self.smi.engine,"smi","control")
        self.access.runtime_preflight(self.core.engine,"genesis","core")
        self.core.read_pre_genesis_state(); self._sources(); self._smi_intent(smi_request)
        body=prepared_body(genesis_request,PreparedGenesis,("authority_reference","intent_id","opening_wire","activation_approval"))
        if body["authority_reference"]!=self.authority.target.authority_reference or body["intent_id"]!=self._smi_intent(smi_request).intent_id or c2(body["activation_approval"])!=self.policy.activation_approval_wire:
            fail("GENESIS_REQUEST_SUBSTITUTION")
        if decode(smi_request.wire)["authority_hash"]!=activation_hash("authority",authority_request.wire): fail("SMI_AUTHORITY_SUBSTITUTION")
        verify_opening(decode_opening(bytes.fromhex(body["opening_wire"])),self.core.configuration)
        self.recovery.verify("pre_activation",sha(authority_request.wire))
        a=self.execute_authority(authority_request,confirmation=authority_confirmation)
        if a["reconciliation_required"]: return a
        signed=self.sign_smi(smi_request,confirmation=smi_confirmation)
        s=self.execute_smi(signed,now=now,confirmation=smi_confirmation)
        if s["reconciliation_required"]: return s
        package=self.owner_request_package(genesis_request)
        return {"status":"GENESIS_FINAL_OWNER_CONFIRMATION_REQUIRED","owner_request_package":decode(package.wire),
                "GENESIS_mutation_attempted":False,"VerifiedGenesisAuthorization_present":False}

    def _send(self,operation,request,send,readback):
        # No loop and no error-to-success conversion. Once send begins, broad
        # transport/commit errors are UNKNOWN until a separate explicit probe.
        try:
            value=send()
        except DBAPIError:
            return self._result(operation,request,"UNKNOWN",True,True)
        except CoreError as exc:
            if any(x in str(exc) for x in ("DATABASE_ERROR","OUTCOME_UNKNOWN","RECONCILIATION_REQUIRED")):
                return self._result(operation,request,"UNKNOWN",True,True)
            raise
        state=readback()
        result=self._result(operation,request,state,True,"UNKNOWN" in state or state.endswith("ABSENT") or state=="PRE_GENESIS")
        result["canonical_outcome"]=value.get("outcome") if isinstance(value,dict) else value.outcome
        if "CONFLICT" in state: result["next_gate"]="STOP_CONFLICT"
        return result

    def _result(self,operation,request,state,attempted,uncertain):
        return {"operation":operation,"target":self.policy.access.core_database if operation=="genesis" else self.policy.access.control_database,
                "environment":"PRODUCTION" if self.policy.access.classification==REAL_PRODUCTION else "NON_PRODUCTION",
                "actor":self.policy.access.role(operation),"prepared_request_hash":sha(request.wire),
                "authorization_state":"GOVERNANCE_REVALIDATED","confirmation_state":"EXACT",
                "preflight_state":"OPERATION_READY","mutation_attempted":attempted,"durable_state":state,
                "readback_state":state,"reconciliation_required":uncertain,
                "transition":"OWNER_APPROVED_TO_ACTIVATION_EXECUTING_BEFORE_AUTHORITY_SEND" if operation=="authority" else None,
                "next_gate":"READ_ONLY_RECONCILIATION" if uncertain else "ACCEPTANCE_VERIFYING" if operation=="genesis" and state=="GENESIS_DURABLE_EXACT" else "EXPLICIT_NEXT_STAGE"}
