"""DDL for the Slice04 durable ordinary-authorization provider.

The schema is installed explicitly by the existing owner/migrator path.  The
online application receives only the SECURITY DEFINER functions below; it has
no direct table access and cannot manufacture an Operator policy.
"""

SQL = r"""
CREATE TABLE control_plane.r1d_subjects (
 scope_id uuid NOT NULL REFERENCES control_plane.r1s_scopes(scope_id),
 runtime_principal text NOT NULL,
 policy_digest text NOT NULL CHECK(policy_digest ~ '^[0-9a-f]{64}$'),
 session_id uuid NOT NULL,
 policy_wire bytea NOT NULL,
 session_wire bytea NOT NULL,
 credential_digest text NOT NULL CHECK(credential_digest ~ '^[0-9a-f]{64}$'),
 active boolean NOT NULL DEFAULT true,
 PRIMARY KEY(scope_id,runtime_principal),
 UNIQUE(scope_id,session_id), UNIQUE(scope_id,credential_digest)
);
CREATE TABLE control_plane.r1d_issues (
 scope_id uuid NOT NULL REFERENCES control_plane.r1s_scopes(scope_id),
 issue_id uuid NOT NULL, issue_kind text NOT NULL CHECK(issue_kind IN ('GRANT','PERMIT')),
 operation_id uuid NOT NULL, issue_sequence bigint NOT NULL CHECK(issue_sequence > 0),
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 subject_principal text NOT NULL, session_id uuid NOT NULL,
 inventory_digest text NOT NULL CHECK(inventory_digest ~ '^[0-9a-f]{64}$'),
 object_digest text NOT NULL CHECK(object_digest ~ '^[0-9a-f]{64}$'),
 object_wire bytea NOT NULL, authority_sequence bigint NOT NULL CHECK(authority_sequence > 0),
 committed_at_ms bigint NOT NULL,
 PRIMARY KEY(scope_id,issue_id), UNIQUE(scope_id,issue_kind,operation_id,issue_sequence),
 UNIQUE(scope_id,object_digest)
);
CREATE TABLE control_plane.r1d_revocations (
 scope_id uuid NOT NULL REFERENCES control_plane.r1s_scopes(scope_id),
 revoke_kind text NOT NULL CHECK(revoke_kind IN ('POLICY_REVOKE','SESSION_REVOKE','LEASE_REVOKE','GRANT_REVOKE','PERMIT_REVOKE')),
 object_digest text NOT NULL CHECK(object_digest ~ '^[0-9a-f]{64}$'),
 authorization_wire bytea NOT NULL, authority_sequence bigint NOT NULL CHECK(authority_sequence > 0),
 committed_at_ms bigint NOT NULL,
 PRIMARY KEY(scope_id,revoke_kind,object_digest)
);
CREATE FUNCTION control_plane.r1d_subject(sid uuid, principal text)
RETURNS SETOF control_plane.r1d_subjects LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,control_plane,pg_temp AS $$
 SELECT s.* FROM control_plane.r1d_subjects s WHERE s.scope_id=sid AND s.runtime_principal=principal
$$;
CREATE FUNCTION control_plane.r1d_subject_by_credential(sid uuid, digest text)
RETURNS TABLE(runtime_principal text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,control_plane,pg_temp AS $$
 SELECT s.runtime_principal FROM control_plane.r1d_subjects s
 WHERE s.scope_id=sid AND s.credential_digest=digest AND s.active
$$;
CREATE FUNCTION control_plane.r1d_issue(sid uuid, iid uuid)
RETURNS SETOF control_plane.r1d_issues LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,control_plane,pg_temp AS $$
 SELECT i.* FROM control_plane.r1d_issues i WHERE i.scope_id=sid AND i.issue_id=iid
$$;
CREATE FUNCTION control_plane.r1d_current_issue(sid uuid,kind text,op uuid)
RETURNS SETOF control_plane.r1d_issues LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,control_plane,pg_temp AS $$
 SELECT i.* FROM control_plane.r1d_issues i
 WHERE i.scope_id=sid AND i.issue_kind=kind AND i.operation_id=op
 ORDER BY i.issue_sequence DESC LIMIT 1
$$;
CREATE FUNCTION control_plane.r1d_revocation(sid uuid,kind text,object_hash text)
RETURNS SETOF control_plane.r1d_revocations LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,control_plane,pg_temp AS $$
 SELECT r.* FROM control_plane.r1d_revocations r
 WHERE r.scope_id=sid AND r.revoke_kind=kind AND r.object_digest=object_hash
$$;
CREATE FUNCTION control_plane.r1d_install_subject(sid uuid, principal text, pd text, sess uuid,
 policy_bytes bytea, session_bytes bytea, credential_hash text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,control_plane,pg_temp AS $$
DECLARE old control_plane.r1d_subjects;
BEGIN
 PERFORM 1 FROM control_plane.r1s_scopes WHERE scope_id=sid FOR UPDATE;
 SELECT * INTO old FROM control_plane.r1d_subjects WHERE scope_id=sid AND runtime_principal=principal;
 IF FOUND THEN
  IF old.policy_digest<>pd OR old.session_id<>sess OR old.policy_wire<>policy_bytes
   OR old.session_wire<>session_bytes OR old.credential_digest<>credential_hash
  THEN PERFORM control_plane.r1s_fail('DURABLE_SUBJECT_CONFLICT'); END IF;
 ELSE INSERT INTO control_plane.r1d_subjects VALUES
  (sid,principal,pd,sess,policy_bytes,session_bytes,credential_hash,true); END IF;
END $$;
CREATE FUNCTION control_plane.r1d_record_issue(sid uuid,iid uuid,kind text,op uuid,seq bigint,
 request_hash text,principal text,sess uuid,inventory_hash text,object_hash text,
 object_bytes bytea,event_sequence bigint,at_ms bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,control_plane,pg_temp AS $$
DECLARE old control_plane.r1d_issues;
BEGIN
 PERFORM 1 FROM control_plane.r1s_scopes WHERE scope_id=sid FOR UPDATE;
 SELECT * INTO old FROM control_plane.r1d_issues WHERE scope_id=sid AND issue_id=iid;
 IF FOUND THEN
  IF old.issue_kind<>kind OR old.operation_id<>op OR old.issue_sequence<>seq
   OR old.request_digest<>request_hash OR old.subject_principal<>principal OR old.session_id<>sess
   OR old.inventory_digest<>inventory_hash OR old.object_digest<>object_hash OR old.object_wire<>object_bytes
   OR old.authority_sequence<>event_sequence
  THEN PERFORM control_plane.r1s_fail('DURABLE_ISSUE_CONFLICT'); END IF;
 ELSE
  INSERT INTO control_plane.r1d_issues VALUES
   (sid,iid,kind,op,seq,request_hash,principal,sess,inventory_hash,object_hash,object_bytes,event_sequence,at_ms);
 END IF;
END $$;
CREATE FUNCTION control_plane.r1d_record_revocation(sid uuid,kind text,object_hash text,
 authorization_bytes bytea,event_sequence bigint,at_ms bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,control_plane,pg_temp AS $$
DECLARE old control_plane.r1d_revocations;
BEGIN
 PERFORM 1 FROM control_plane.r1s_scopes WHERE scope_id=sid FOR UPDATE;
 SELECT * INTO old FROM control_plane.r1d_revocations
  WHERE scope_id=sid AND revoke_kind=kind AND object_digest=object_hash;
 IF FOUND THEN
  IF old.authorization_wire<>authorization_bytes OR old.authority_sequence<>event_sequence
  THEN PERFORM control_plane.r1s_fail('DURABLE_REVOKE_CONFLICT'); END IF;
 ELSE INSERT INTO control_plane.r1d_revocations VALUES
  (sid,kind,object_hash,authorization_bytes,event_sequence,at_ms); END IF;
END $$;
REVOKE ALL ON control_plane.r1d_subjects,control_plane.r1d_issues,control_plane.r1d_revocations
 FROM PUBLIC,control_plane_app,control_plane_reader;
REVOKE ALL ON FUNCTION control_plane.r1d_subject(uuid,text),
 control_plane.r1d_subject_by_credential(uuid,text),control_plane.r1d_issue(uuid,uuid),
 control_plane.r1d_current_issue(uuid,text,uuid),control_plane.r1d_revocation(uuid,text,text),
 control_plane.r1d_install_subject(uuid,text,text,uuid,bytea,bytea,text),
 control_plane.r1d_record_issue(uuid,uuid,text,uuid,bigint,text,text,uuid,text,text,bytea,bigint,bigint),
 control_plane.r1d_record_revocation(uuid,text,text,bytea,bigint,bigint)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control_plane.r1d_subject(uuid,text),
 control_plane.r1d_subject_by_credential(uuid,text),control_plane.r1d_issue(uuid,uuid),
 control_plane.r1d_current_issue(uuid,text,uuid),control_plane.r1d_revocation(uuid,text,text),
 control_plane.r1d_install_subject(uuid,text,text,uuid,bytea,bytea,text),
 control_plane.r1d_record_issue(uuid,uuid,text,uuid,bigint,text,text,uuid,text,text,bytea,bigint,bigint),
 control_plane.r1d_record_revocation(uuid,text,text,bytea,bigint,bigint)
 TO control_plane_app;
"""
