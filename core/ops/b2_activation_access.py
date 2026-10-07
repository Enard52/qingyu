"""Fixed activation ACLs. Composition is trusted; execution has no SQL/role input.

Provisioning is an explicitly confirmed administrative operation, never a runtime
actor privilege. Synthetic composition changes physical names only in its own
isolated PostgreSQL. No credentials are accepted by operational requests.
"""
from dataclasses import dataclass
from sqlalchemy import text
from app.errors import CoreError

ROLE_CONFIRMATION = "PROVISION_FIXED_B2_ACTIVATION_ROLES_AND_ACLS"
ROLES = {
    "control_migrator": "qingyu_control_migrator",
    "core_migrator": "qingyu_prod_migrator",
    "authority": "qingyu_activation_authority",
    "smi": "qingyu_activation_smi",
    "genesis": "qingyu_activation_genesis",
    "reader": "qingyu_activation_reader",
}
OWNERS = {"control": "qingyu_control_owner", "core": "qingyu_prod_owner"}
TABLES = {
    "control": ("governance.schema_migrations", "governance.production_trust_records",
                "governance.production_signer_admission_records",
                "governance.production_signer_admission_trust_bindings",
                "governance.activation_migrations", "governance.activation_authorities",
                "governance.activation_smis"),
    "core": ("r1_core_v2.activation_migrations", "r1_core_v2.identity",
             "r1_core_v2.genesis", "r1_core_v2.lifecycle"),
}
INSERTS = {"authority": ("governance.activation_authorities",),
           "smi": ("governance.activation_smis",),
           "genesis": ("r1_core_v2.identity", "r1_core_v2.genesis", "r1_core_v2.lifecycle"),
           "reader": ()}
PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


def fail(code):
    raise CoreError("B2_OPS_" + code)


@dataclass(frozen=True)
class AccessPolicy:
    """Installed by deployment composition, never decoded from a request."""
    classification: str
    control_database: str
    core_database: str
    synthetic_suffix: str = ""
    endpoint_port: int = 5433

    def __post_init__(self):
        import re
        if self.classification == "REAL_PRODUCTION":
            if (self.control_database, self.core_database, self.synthetic_suffix) != ("qingyu_control", "qingyu_prod", ""):
                fail("TARGET_MISMATCH")
            if self.endpoint_port!=5433: fail("ENDPOINT_MISMATCH")
        elif self.classification == "SYNTHETIC_TEST":
            if (not re.fullmatch(r"[0-9a-f]{10}", self.synthetic_suffix)
                    or any(not re.fullmatch(r"synthetic_[a-z]+_[0-9a-f]{10}", n)
                           for n in (self.control_database, self.core_database))):
                fail("SYNTHETIC_TARGET_REQUIRED")
        else:
            fail("CLASSIFICATION_MISMATCH")
        if type(self.endpoint_port) is not int or not 1<=self.endpoint_port<=65535: fail("ENDPOINT_MISMATCH")

    def role(self, actor):
        if actor not in ROLES:
            fail("ACTOR_MISMATCH")
        return ROLES[actor] if self.classification == "REAL_PRODUCTION" else "synthetic_" + actor + "_" + self.synthetic_suffix

    def owner(self, kind):
        if kind not in OWNERS:
            fail("TARGET_MISMATCH")
        return OWNERS[kind] if self.classification == "REAL_PRODUCTION" else "synthetic_" + kind + "_owner_" + self.synthetic_suffix

    def database(self, kind):
        if kind not in OWNERS:
            fail("TARGET_MISMATCH")
        return self.control_database if kind == "control" else self.core_database


class FixedAccess:
    def __init__(self, policy, *, recovery=None):
        if type(policy) is not AccessPolicy:
            fail("PROTECTED_COMPOSITION_REQUIRED")
        self.policy = policy
        self.recovery = recovery

    def provisioning_plan_hash(self,stage):
        from dataclasses import asdict
        from app.control_plane.r1_validation_codec import c2,sha
        if stage not in {"roles","acl"}: fail("PROVISIONING_STAGE_MISMATCH")
        return sha(c2({"stage":stage,"policy":asdict(self.policy),"roles":ROLES,"owners":OWNERS,
                       "tables":TABLES,"inserts":INSERTS,"default":"DENY"}))

    def _recovery_guard(self,stage,admin_control):
        if self.policy.classification!="REAL_PRODUCTION": return
        from .b2_activation_operations import RecoveryBoundary
        if type(self.recovery) is not RecoveryBoundary or self.recovery.classification!="REAL_PRODUCTION":
            fail("FRESH_RECOVERY_ANCHOR_REQUIRED")
        self.recovery.verify(stage,self.provisioning_plan_hash(stage))
        self.admin_endpoint(admin_control,"control")
        with admin_control.connect() as c:
            hashes=c.execute(text("SELECT binding_hash FROM governance.production_signer_admission_trust_bindings WHERE admission_reference='qingyu-prod-signer-admission-01'")).scalars().all()
            if hashes!=[self.recovery.binding_hash]: fail("RECOVERY_BINDING_MISMATCH")

    def endpoint(self,engine,kind):
        url=engine.url
        if (url.drivername,url.host,url.port,url.database)!=("postgresql+psycopg","127.0.0.1",self.policy.endpoint_port,self.policy.database(kind)) or url.query:
            fail("ENDPOINT_MISMATCH")

    def admin_endpoint(self,engine,kind):
        # Existing guest OS postgres custody uses peer auth on the fixed local
        # socket, never a runtime or request-selectable endpoint. No invented
        # administrative TCP password or new credential source is required.
        url=engine.url
        if self.policy.classification=="REAL_PRODUCTION" and (
                url.drivername,url.host,url.port,url.database,url.username)==(
                "postgresql+psycopg","/var/run/postgresql",5433,self.policy.database(kind),"postgres") and not url.query:
            return
        self.endpoint(engine,kind)

    def identity(self, connection, actor, kind, *, owner_context=False):
        session, current, database = connection.execute(text("SELECT session_user, current_user, current_database()")).one()
        expected = self.policy.owner(kind) if owner_context else self.policy.role(actor)
        if (session, current, database) != (self.policy.role(actor), expected, self.policy.database(kind)):
            fail("SESSION_ACTOR_OR_TARGET_MISMATCH")

    def runtime_preflight(self, engine, actor, kind):
        if actor not in INSERTS or (actor in {"authority", "smi"} and kind != "control") or (actor == "genesis" and kind != "core"):
            fail("ACTOR_MISMATCH")
        self.endpoint(engine,kind)
        with engine.connect() as c:
            self.identity(c, actor, kind)
            flags = c.execute(text("SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls FROM pg_roles WHERE rolname=current_user")).one()
            if any(flags): fail("EXCESS_ROLE_PRIVILEGE")
            membership = c.execute(text("SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user)")).scalar_one()
            if membership: fail("EXCESS_ROLE_MEMBERSHIP")
            db = c.execute(text("SELECT has_database_privilege(current_database(),'CONNECT'), has_database_privilege(current_database(),'TEMP'), has_database_privilege(current_database(),'CREATE'), (SELECT datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user) FROM pg_database WHERE datname=current_database())")).one()
            if tuple(db) != (True, False, False, False): fail("DATABASE_ACL_MISMATCH")
            other=self.policy.database("core" if kind=="control" else "control")
            if actor!="reader" and c.execute(text("SELECT has_database_privilege(:db,'CONNECT')"),{"db":other}).scalar_one():
                fail("CROSS_DATABASE_ACL_MISMATCH")
            schema = "governance" if kind == "control" else "r1_core_v2"
            if tuple(c.execute(text("SELECT has_schema_privilege(:s,'USAGE'),has_schema_privilege(:s,'CREATE'), (SELECT nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user) FROM pg_namespace WHERE nspname=:s)"), {"s":schema}).one()) != (True, False, False):
                fail("SCHEMA_ACL_MISMATCH")
            objects = c.execute(text("SELECT n.nspname||'.'||p.relname FROM pg_class p JOIN pg_namespace n ON n.oid=p.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND p.relkind IN ('r','p','v','m')")).scalars().all()
            matrix = {}
            for table in objects:
                permissions = {priv: bool(c.execute(text("SELECT has_table_privilege(:t,:p)"), {"t":table,"p":priv}).scalar_one()) for priv in PRIVILEGES}
                allowed_read = table in TABLES[kind] or (kind == "core" and table in {"public.genesis_records", "public.core_metadata"})
                wanted = {priv: (allowed_read if priv == "SELECT" else table in INSERTS[actor] if priv == "INSERT" else False) for priv in PRIVILEGES}
                if permissions != wanted: fail("TABLE_ACL_MISMATCH")
                matrix[table] = permissions
            if not set(TABLES[kind]).issubset(objects): fail("SCHEMA_REQUIRED")
            extra = c.execute(text("SELECT EXISTS(SELECT 1 FROM pg_class p JOIN pg_namespace n ON n.oid=p.relnamespace WHERE p.relkind='S' AND n.nspname NOT IN ('pg_catalog','information_schema') AND (has_sequence_privilege(p.oid,'USAGE') OR has_sequence_privilege(p.oid,'SELECT') OR has_sequence_privilege(p.oid,'UPDATE'))), EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND has_function_privilege(p.oid,'EXECUTE'))")).one()
            if any(extra): fail("SEQUENCE_OR_FUNCTION_ACL_MISMATCH")
            return {"state":"ACL_READY", "actor":self.policy.role(actor), "tables":matrix}

    def probe_roles(self,admin_control,admin_core):
        """Read-only administrative readiness; never provisions or reads secrets."""
        found={}
        for engine,kind in ((admin_control,"control"),(admin_core,"core")):
            self.admin_endpoint(engine,kind)
            with engine.connect() as c:
                if c.execute(text("SELECT current_database()")).scalar_one()!=self.policy.database(kind): fail("TARGET_MISMATCH")
                for actor in ROLES:
                    role=self.policy.role(actor)
                    row=c.execute(text("SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=:r"),{"r":role}).one_or_none()
                    found[actor]="ABSENT" if row is None else "UNSAFE" if any(row) else "SAFE_FLAGS"
        return {"state":"CONFIG_VALID","roles":found,"mutation_attempted":False}

    def provision(self, admin_control, admin_core, *, confirmation):
        """Fixed administrative bootstrap; no passwords, DSNs or SQL arguments.

        Creates LOGIN actors with no password and NOLOGIN owners. Credential
        enrollment is a separate approved protected deployment prerequisite,
        never a raw password request. Existing roles must have exact safe flags;
        this never resets passwords or silently changes role attributes.
        """
        if confirmation != ROLE_CONFIRMATION: fail("ROLE_CONFIRMATION_REQUIRED")
        self._recovery_guard("roles",admin_control)
        for engine,kind in ((admin_control,"control"),(admin_core,"core")):
            self.admin_endpoint(engine,kind)
            with engine.begin() as c:
                if c.execute(text("SELECT current_database()")).scalar_one() != self.policy.database(kind): fail("TARGET_MISMATCH")
                if not c.execute(text("SELECT rolsuper FROM pg_roles WHERE rolname=session_user")).scalar_one(): fail("ADMINISTRATIVE_BOOTSTRAP_REQUIRED")
                names=[self.policy.owner(kind)]+[self.policy.role(a) for a in ROLES if a==kind+"_migrator" or a=="reader" or (kind=="control" and a in {"authority","smi"}) or (kind=="core" and a=="genesis")]
                for name in names:
                    row=c.execute(text("SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=:r"),{"r":name}).one_or_none()
                    if row is None:
                        login="NOLOGIN" if name==self.policy.owner(kind) else "LOGIN"
                        c.exec_driver_sql('CREATE ROLE "'+name+'" '+login+' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS')
                    elif any(row): fail("EXISTING_ROLE_UNSAFE")
                owner=self.policy.owner(kind); migrator=self.policy.role(kind+"_migrator")
                c.exec_driver_sql('GRANT "'+owner+'" TO "'+migrator+'" WITH INHERIT FALSE, SET TRUE')
                db=self.policy.database(kind)
                c.exec_driver_sql('REVOKE ALL ON DATABASE "'+db+'" FROM PUBLIC')
                for name in names:
                    c.exec_driver_sql('GRANT CONNECT ON DATABASE "'+db+'" TO "'+name+'"')
                c.exec_driver_sql('GRANT CREATE ON DATABASE "'+db+'" TO "'+owner+'"')
                c.exec_driver_sql('REVOKE CREATE ON SCHEMA public FROM PUBLIC')
        return {"operation":"fixed_role_provisioning","confirmation_state":"EXACT",
                "mutation_attempted":True,"durable_state":"ROLES_PROVISIONED_CREDENTIAL_ENROLLMENT_REQUIRED",
                "next_gate":"READ_ONLY_ROLE_AND_CREDENTIAL_PREFLIGHT"}

    def provision_object_acls(self, admin_control, admin_core, *, confirmation):
        if confirmation != ROLE_CONFIRMATION: fail("ROLE_CONFIRMATION_REQUIRED")
        self._recovery_guard("acl",admin_control)
        for engine,kind in ((admin_control,"control"),(admin_core,"core")):
            self.admin_endpoint(engine,kind)
            schema="governance" if kind=="control" else "r1_core_v2"
            with engine.begin() as c:
                if c.execute(text("SELECT current_database()")).scalar_one()!=self.policy.database(kind): fail("TARGET_MISMATCH")
                if not c.execute(text("SELECT rolsuper FROM pg_roles WHERE rolname=session_user")).scalar_one(): fail("ADMINISTRATIVE_BOOTSTRAP_REQUIRED")
                c.exec_driver_sql('REVOKE ALL ON SCHEMA '+schema+' FROM PUBLIC')
                c.exec_driver_sql('REVOKE ALL ON ALL TABLES IN SCHEMA '+schema+' FROM PUBLIC')
                c.exec_driver_sql('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA '+schema+' FROM PUBLIC')
                actors=("authority","smi","reader") if kind=="control" else ("genesis","reader")
                for actor in actors:
                    role=self.policy.role(actor)
                    c.exec_driver_sql('REVOKE ALL ON ALL TABLES IN SCHEMA '+schema+' FROM "'+role+'"')
                    c.exec_driver_sql('GRANT USAGE ON SCHEMA '+schema+' TO "'+role+'"')
                    c.exec_driver_sql('GRANT SELECT ON '+','.join(TABLES[kind])+' TO "'+role+'"')
                    if INSERTS[actor]: c.exec_driver_sql('GRANT INSERT ON '+','.join(INSERTS[actor])+' TO "'+role+'"')
                if kind=="core":
                    for name in ("genesis_records","core_metadata"):
                        if c.execute(text("SELECT to_regclass(:t)"),{"t":"public."+name}).scalar_one():
                            for actor in actors: c.exec_driver_sql('GRANT SELECT ON public.'+name+' TO "'+self.policy.role(actor)+'"')
        return {"operation":"fixed_object_acl_provisioning","confirmation_state":"EXACT",
                "mutation_attempted":True,"next_gate":"EFFECTIVE_ACL_PREFLIGHT"}
