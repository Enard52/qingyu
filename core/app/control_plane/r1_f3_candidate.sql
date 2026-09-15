-- F3 candidate extension, NOT the admitted initial migration.
-- Installed only by the explicit owner/test installer after the six-table baseline.
ALTER TABLE control_plane.cp_continuities
  ADD COLUMN lease_id uuid,
  ADD COLUMN recovery_state text NOT NULL DEFAULT 'QUARANTINED'
    CHECK (recovery_state IN ('ACTIVE','QUARANTINED','PREPARED')),
  ADD COLUMN genesis_operation_id uuid,
  ADD COLUMN core_audit_head_hash varchar(64),
  ADD COLUMN core_audit_sequence bigint CHECK (core_audit_sequence >= 0);

ALTER TABLE control_plane.cp_operations
  ADD COLUMN request_wire bytea,
  ADD COLUMN prepare_wire bytea,
  ADD COLUMN terminal_wire bytea,
  ADD COLUMN creator_scope jsonb,
  ADD COLUMN f3_proposal jsonb,
  ADD COLUMN f3_proposal_wire bytea,
  ADD COLUMN f3_proposal_xid xid8,
  ADD COLUMN f3_proposal_pid integer,
  ADD COLUMN f3_finalized_xid xid8,
  ADD COLUMN f3_deadline timestamptz,
  ADD COLUMN f3_authorization_wire bytea;

ALTER DEFAULT PRIVILEGES FOR ROLE control_plane_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE FUNCTION control_plane.f3_fail(code text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, control_plane, pg_temp AS $$
BEGIN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='R1_F3_' || code; END;
$$;

-- Deliberately only flat scalar protocol objects; never an arbitrary JSON JCS codec.
CREATE FUNCTION control_plane.f3_flat_jcs(value jsonb) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, control_plane, pg_temp AS $$
DECLARE item record; encoded text := '{'; separator text := ''; kind text; number numeric;
BEGIN
  IF jsonb_typeof(value) <> 'object' THEN PERFORM control_plane.f3_fail('CANONICAL_SHAPE'); END IF;
  FOR item IN SELECT key, val FROM jsonb_each(value) AS e(key,val) ORDER BY key COLLATE "C" LOOP
    IF item.key !~ '^[a-z_][a-z_0-9]*$' THEN PERFORM control_plane.f3_fail('CANONICAL_KEY'); END IF;
    kind := jsonb_typeof(item.val);
    IF kind NOT IN ('string','null','number') THEN PERFORM control_plane.f3_fail('CANONICAL_SCALAR'); END IF;
    IF kind = 'number' THEN
      number := (item.val #>> '{}')::numeric;
      IF trunc(number) <> number OR abs(number) > 9007199254740991 THEN
        PERFORM control_plane.f3_fail('CANONICAL_INTEGER');
      END IF;
      encoded := encoded || separator || to_jsonb(item.key)::text || ':' || trunc(number)::bigint::text;
    ELSE
      encoded := encoded || separator || to_jsonb(item.key)::text || ':' || item.val::text;
    END IF;
    separator := ',';
  END LOOP;
  RETURN convert_to(encoded || '}', 'UTF8');
END;
$$;

CREATE FUNCTION control_plane.f3_frozen_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, control_plane, pg_temp AS $$
-- PostgreSQL computes stored generated columns AFTER BEFORE ROW triggers;
-- protect their source fields, not the transient NEW generated projection.
DECLARE mutable text[] := ARRAY['existing_continuity_id','state','prepare_ack','prepare_wire','local_commit_attestation_hash',
 'result_code','result_payload_hash','result_payload','continuity_epoch','control_plane_generation_id',
 'owner_version','lease_generation','receipt_key_id','authority_sequence','previous_receipt_hash',
 'receipt_hash','receipt_payload','receipt_signature','decided_at','terminal_wire','f3_proposal',
 'f3_proposal_wire','f3_proposal_xid','f3_proposal_pid','f3_finalized_xid','f3_deadline','f3_authorization_wire'];
BEGIN
  IF TG_OP = 'DELETE' OR OLD.state IN ('COMMITTED','ABORTED') THEN
    PERFORM control_plane.f3_fail('IMMUTABLE_HISTORY');
  END IF;
  IF (to_jsonb(OLD) - mutable) IS DISTINCT FROM (to_jsonb(NEW) - mutable) THEN
    PERFORM control_plane.f3_fail('IMMUTABLE_INTENT');
  END IF;
  IF OLD.prepare_wire IS NOT NULL AND (OLD.prepare_wire IS DISTINCT FROM NEW.prepare_wire
      OR OLD.prepare_ack IS DISTINCT FROM NEW.prepare_ack) THEN
    PERFORM control_plane.f3_fail('IMMUTABLE_PREPARE_ACK');
  END IF;
  IF OLD.f3_authorization_wire IS NOT NULL AND OLD.f3_authorization_wire IS DISTINCT FROM NEW.f3_authorization_wire THEN
    PERFORM control_plane.f3_fail('IMMUTABLE_AUTHORIZATION');
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER f3_immutable_operation BEFORE UPDATE OR DELETE ON control_plane.cp_operations
FOR EACH ROW EXECUTE FUNCTION control_plane.f3_frozen_guard();

CREATE FUNCTION control_plane.f3_commit_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, control_plane, pg_temp AS $$
DECLARE current_row control_plane.cp_operations;
BEGIN
  SELECT * INTO current_row FROM control_plane.cp_operations
    WHERE authority_domain_id=NEW.authority_domain_id AND operation_id=NEW.operation_id;
  IF current_row.request_wire IS NULL THEN RETURN NULL; END IF;
  IF current_row.f3_proposal IS NOT NULL OR current_row.prepare_wire IS NULL THEN
    PERFORM control_plane.f3_fail('UNFINALIZED_PROPOSAL');
  END IF;
  IF current_row.f3_finalized_xid = pg_current_xact_id()
      AND (current_row.f3_deadline IS NULL OR clock_timestamp() >= current_row.f3_deadline) THEN
    PERFORM control_plane.f3_fail('COMMIT_EXPIRED');
  END IF;
  RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER f3_transaction_completion AFTER INSERT OR UPDATE ON control_plane.cp_operations
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION control_plane.f3_commit_guard();

CREATE FUNCTION control_plane.f3_check_caller(e jsonb, caller jsonb) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, control_plane, pg_temp AS $$
BEGIN
  IF caller IS NULL OR caller <> jsonb_build_object(
      'authority_domain_id',e->>'authority_domain_id','continuity_id',e->>'continuity_id',
      'caller_runtime_id',e->>'caller_runtime_id','session_id',e->'payload'->>'session_id',
      'storage_generation_id',e->>'storage_generation_id','actor_identity',e->>'actor_or_owner_identity') THEN
    PERFORM control_plane.f3_fail('CALLER_SCOPE');
  END IF;
END;
$$;

-- All entrypoints lock generation, continuity, operation, then session/key.
CREATE FUNCTION control_plane.f3_lock_scope(e jsonb) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, control_plane, pg_temp AS $$
BEGIN
  PERFORM 1 FROM control_plane.cp_generations WHERE authority_domain_id=(e->>'authority_domain_id')::uuid
    AND authority_generation=(e->>'authority_generation')::bigint FOR UPDATE;
  IF NOT FOUND THEN PERFORM control_plane.f3_fail('AUTHORITY_MISSING'); END IF;
  PERFORM 1 FROM control_plane.cp_continuities WHERE authority_domain_id=(e->>'authority_domain_id')::uuid
    AND continuity_id=(e->>'continuity_id')::uuid FOR UPDATE;
  IF NOT FOUND THEN PERFORM control_plane.f3_fail('CONTINUITY_MISSING'); END IF;
END;
$$;

CREATE FUNCTION control_plane.f3_check_current(e jsonb) RETURNS timestamptz
LANGUAGE plpgsql SET search_path = pg_catalog, control_plane, pg_temp AS $$
DECLARE c control_plane.cp_continuities; g control_plane.cp_generations;
 s control_plane.cp_runtime_sessions; k control_plane.cp_receipt_keys; p jsonb := e->'payload';
 deadline timestamptz;
BEGIN
  SELECT * INTO g FROM control_plane.cp_generations WHERE authority_domain_id=(e->>'authority_domain_id')::uuid
    AND authority_generation=(e->>'authority_generation')::bigint;
  IF NOT FOUND OR g.status <> 'ACTIVE' OR g.authority_instance_id <> (e->>'authority_instance_id')::uuid THEN
    PERFORM control_plane.f3_fail('AUTHORITY_FENCED'); END IF;
  SELECT * INTO c FROM control_plane.cp_continuities WHERE authority_domain_id=g.authority_domain_id
    AND continuity_id=(e->>'continuity_id')::uuid;
  IF NOT FOUND OR c.qingyu_identity_id <> (e->>'qingyu_identity_id')::uuid
      OR c.continuity_epoch <> (e->>'expected_continuity_epoch')::bigint
      OR c.state_version <> (e->>'expected_state_version')::bigint
      OR c.owner_version <> (e->>'expected_owner_version')::bigint
      OR c.owner_identity <> e->>'actor_or_owner_identity'
      OR c.active_storage_generation_id <> (e->>'storage_generation_id')::uuid
      OR c.control_plane_generation_id <> (p->>'control_plane_generation_id')::uuid THEN
    PERFORM control_plane.f3_fail('STATE_FENCED'); END IF;
  IF c.recovery_state <> 'ACTIVE' OR c.admission_state <> 'OPEN' THEN
    PERFORM control_plane.f3_fail('ADMISSION_FENCED'); END IF;
  IF c.genesis_operation_id IS DISTINCT FROM (p->>'genesis_operation_id')::uuid OR NOT EXISTS (
      SELECT 1 FROM control_plane.cp_operations genesis WHERE genesis.authority_domain_id=c.authority_domain_id
        AND genesis.operation_id=c.genesis_operation_id AND genesis.continuity_id=c.continuity_id
        AND genesis.qingyu_identity_id=c.qingyu_identity_id AND genesis.operation_type='AUTHORITY_GENESIS_ACTIVATION'
        AND genesis.state='COMMITTED' AND genesis.receipt_hash IS NOT NULL
        AND octet_length(genesis.receipt_signature)=64) THEN
    PERFORM control_plane.f3_fail('GENESIS_FENCED'); END IF;
  IF c.core_audit_sequence IS NULL OR c.core_audit_head_hash IS DISTINCT FROM p->>'core_audit_predecessor_hash' THEN
    PERFORM control_plane.f3_fail('AUDIT_FENCED'); END IF;
  IF c.lease_status <> 'ACTIVE' OR c.lease_id IS DISTINCT FROM (p->>'lease_id')::uuid
      OR c.lease_generation <> (p->>'lease_generation')::bigint
      OR c.lease_runtime_id IS DISTINCT FROM (e->>'caller_runtime_id')::uuid
      OR c.lease_session_id IS DISTINCT FROM (p->>'session_id')::uuid
      OR c.lease_storage_generation_id IS DISTINCT FROM c.active_storage_generation_id
      OR c.lease_epoch IS DISTINCT FROM c.continuity_epoch THEN
    PERFORM control_plane.f3_fail('LEASE_FENCED'); END IF;
  SELECT * INTO s FROM control_plane.cp_runtime_sessions WHERE authority_domain_id=c.authority_domain_id
    AND caller_runtime_id=c.lease_runtime_id AND session_id=c.lease_session_id FOR UPDATE;
  IF NOT FOUND OR s.session_state <> 'ACTIVE' OR s.revoked_at IS NOT NULL
      OR s.continuity_id <> c.continuity_id OR s.storage_generation_id <> c.active_storage_generation_id THEN
    PERFORM control_plane.f3_fail('SESSION_FENCED'); END IF;
  SELECT * INTO k FROM control_plane.cp_receipt_keys WHERE authority_domain_id=g.authority_domain_id
    AND receipt_key_id=g.receipt_key_id FOR UPDATE;
  IF NOT FOUND OR k.revoked_at IS NOT NULL OR k.authority_generation <> g.authority_generation
      OR k.authority_instance_id <> g.authority_instance_id THEN
    PERFORM control_plane.f3_fail('KEY_FENCED'); END IF;
  deadline := least(c.lease_expires_at,s.expires_at);
  IF c.lease_expires_at IS NULL OR s.expires_at IS NULL OR clock_timestamp() >= deadline THEN
    PERFORM control_plane.f3_fail('LEASE_EXPIRED'); END IF;
  RETURN deadline;
END;
$$;

CREATE FUNCTION control_plane.f3_propose_prepare(request_bytes bytea, caller jsonb,
    staged_bytes bytea, abort_bytes bytea)
RETURNS TABLE(operation_id uuid, state text, wire bytea, historical boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, control_plane, pg_temp AS $$
DECLARE e jsonb := convert_from(request_bytes,'UTF8')::jsonb; p jsonb := e->'payload';
 o control_plane.cp_operations; g control_plane.cp_generations; ack jsonb; stamp timestamptz;
 deadline timestamptz; request_hash text := encode(sha256(request_bytes),'hex');
BEGIN
  IF e->>'operation_type' IS DISTINCT FROM 'MUTATION' OR e->>'schema_version' IS DISTINCT FROM '1' OR p->>'payload_version' IS DISTINCT FROM '1'
      OR (SELECT count(*) FROM jsonb_object_keys(e)) <> 16
      OR e - ARRAY['schema_version','authority_domain_id','authority_instance_id','authority_generation',
         'qingyu_identity_id','continuity_id','operation_id','operation_type','expected_continuity_epoch',
         'expected_state_version','expected_owner_version','actor_or_owner_identity','caller_runtime_id',
         'storage_generation_id','payload','reason'] <> '{}'::jsonb
      OR (SELECT count(*) FROM jsonb_object_keys(p)) <> 14
      OR p - ARRAY['payload_version','mutation_id','local_commit_id','lease_id','lease_generation','session_id',
         'control_plane_generation_id','genesis_operation_id','staged_result','staged_result_hash',
         'core_audit_predecessor_hash','core_audit_candidate_hash','abort_result','abort_result_hash'] <> '{}'::jsonb
      OR convert_from(staged_bytes,'UTF8')::jsonb IS DISTINCT FROM p->'staged_result'
      OR convert_from(abort_bytes,'UTF8')::jsonb IS DISTINCT FROM p->'abort_result'
      OR encode(sha256(staged_bytes),'hex') IS DISTINCT FROM p->>'staged_result_hash'
      OR encode(sha256(abort_bytes),'hex') IS DISTINCT FROM p->>'abort_result_hash'
      OR p->'staged_result'->>'mutation_id' IS DISTINCT FROM p->>'mutation_id'
      OR (p->'staged_result'->>'state_version')::bigint <> (e->>'expected_state_version')::bigint + 1
      OR (p->'abort_result'->>'state_version')::bigint <> (e->>'expected_state_version')::bigint
      OR p->'abort_result'->>'mutation_id' IS DISTINCT FROM p->>'mutation_id'
      OR p->'abort_result'->>'result_state' IS DISTINCT FROM 'ABORTED' THEN
    PERFORM control_plane.f3_fail('INTENT_SHAPE'); END IF;
  PERFORM control_plane.f3_check_caller(e,caller);
  PERFORM control_plane.f3_lock_scope(e);
  SELECT * INTO o FROM control_plane.cp_operations x WHERE x.authority_domain_id=(e->>'authority_domain_id')::uuid
    AND x.operation_id=(e->>'operation_id')::uuid FOR UPDATE;
  IF FOUND THEN
    IF o.request_wire IS DISTINCT FROM request_bytes OR o.creator_scope IS DISTINCT FROM caller THEN
      PERFORM control_plane.f3_fail('OPERATION_CONFLICT'); END IF;
    IF o.f3_proposal IS NOT NULL OR o.prepare_wire IS NULL THEN PERFORM control_plane.f3_fail('PROPOSAL_PENDING'); END IF;
    RETURN QUERY SELECT o.operation_id,o.state::text,coalesce(o.terminal_wire,o.prepare_wire),true;
    RETURN;
  END IF;
  deadline := control_plane.f3_check_current(e);
  IF EXISTS (SELECT 1 FROM control_plane.cp_operations x WHERE x.authority_domain_id=(e->>'authority_domain_id')::uuid
      AND x.continuity_id=(e->>'continuity_id')::uuid AND x.state='PREPARED') THEN
    PERFORM control_plane.f3_fail('PREPARED_CONFLICT'); END IF;
  SELECT * INTO g FROM control_plane.cp_generations WHERE authority_domain_id=(e->>'authority_domain_id')::uuid
    AND authority_generation=(e->>'authority_generation')::bigint;
  stamp := clock_timestamp();
  ack := jsonb_build_object('ack_version',1,'authority_domain_id',e->>'authority_domain_id',
    'authority_instance_id',e->>'authority_instance_id','authority_generation',g.authority_generation,
    'qingyu_identity_id',e->>'qingyu_identity_id','continuity_id',e->>'continuity_id',
    'operation_id',e->>'operation_id','operation_type','MUTATION','request_envelope_hash',request_hash,
    'caller_runtime_id',e->>'caller_runtime_id','storage_generation_id',e->>'storage_generation_id',
    'expected_continuity_epoch',(e->>'expected_continuity_epoch')::bigint,
    'expected_owner_version',(e->>'expected_owner_version')::bigint,
    'expected_state_version',(e->>'expected_state_version')::bigint,
    'staged_result_hash',p->>'staged_result_hash','core_audit_predecessor_hash',p->>'core_audit_predecessor_hash',
    'core_audit_candidate_hash',p->>'core_audit_candidate_hash','state','PREPARED',
    'prepared_at',to_char(stamp AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'receipt_key_id',g.receipt_key_id);
  INSERT INTO control_plane.cp_operations(authority_domain_id,operation_id,authority_generation,authority_instance_id,
    qingyu_identity_id,continuity_id,operation_type,request_envelope_hash,request_envelope,caller_runtime_id,
    storage_generation_id,actor_or_owner_identity,expected_continuity_epoch,expected_state_version,expected_owner_version,
    state,prepared_at,prepare_ack,staged_result_hash,core_audit_predecessor_hash,core_audit_candidate_hash,
    request_wire,creator_scope,f3_proposal,f3_proposal_wire,f3_proposal_xid,f3_proposal_pid,f3_deadline)
  VALUES(g.authority_domain_id,(e->>'operation_id')::uuid,g.authority_generation,g.authority_instance_id,
    (e->>'qingyu_identity_id')::uuid,(e->>'continuity_id')::uuid,'MUTATION',request_hash,e,
    (e->>'caller_runtime_id')::uuid,(e->>'storage_generation_id')::uuid,e->>'actor_or_owner_identity',
    (e->>'expected_continuity_epoch')::bigint,(e->>'expected_state_version')::bigint,(e->>'expected_owner_version')::bigint,
    'PREPARED',stamp,'{}'::jsonb,p->>'staged_result_hash',p->>'core_audit_predecessor_hash',p->>'core_audit_candidate_hash',
    request_bytes,caller,ack,control_plane.f3_flat_jcs(ack),pg_current_xact_id(),pg_backend_pid(),deadline);
  RETURN QUERY SELECT (e->>'operation_id')::uuid,'PREPARED'::text,control_plane.f3_flat_jcs(ack),false;
END;
$$;

CREATE FUNCTION control_plane.f3_finalize_prepare(op_id uuid, signature bytea) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, control_plane, pg_temp AS $$
DECLARE o control_plane.cp_operations; result jsonb; result_wire bytea; deadline timestamptz;
BEGIN
  SELECT * INTO o FROM control_plane.cp_operations WHERE operation_id=op_id
    AND f3_proposal_xid=pg_current_xact_id() AND f3_proposal_pid=pg_backend_pid();
  IF NOT FOUND OR o.f3_proposal->>'state' <> 'PREPARED' OR o.prepare_wire IS NOT NULL
      OR o.f3_proposal_wire IS DISTINCT FROM control_plane.f3_flat_jcs(o.f3_proposal)
      OR signature IS NULL OR octet_length(signature) <> 64 THEN
    PERFORM control_plane.f3_fail('PROPOSAL_MISMATCH'); END IF;
  deadline := control_plane.f3_check_current(o.request_envelope);
  result := o.f3_proposal || jsonb_build_object('ack_signature',encode(signature,'hex'));
  result_wire := control_plane.f3_flat_jcs(result);
  UPDATE control_plane.cp_operations SET prepare_ack=result,prepare_wire=result_wire,
    f3_proposal=NULL,f3_proposal_wire=NULL,f3_proposal_xid=NULL,f3_proposal_pid=NULL,
    f3_finalized_xid=pg_current_xact_id(),f3_deadline=least(o.f3_deadline,deadline)
    WHERE authority_domain_id=o.authority_domain_id AND operation_id=o.operation_id AND state='PREPARED';
  RETURN result_wire;
END;
$$;

CREATE FUNCTION control_plane.f3_propose_terminal(request_bytes bytea, caller jsonb, authorization_bytes bytea)
RETURNS TABLE(operation_id uuid, state text, wire bytea, historical boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, control_plane, pg_temp AS $$
DECLARE e jsonb := convert_from(request_bytes,'UTF8')::jsonb; auth jsonb := convert_from(authorization_bytes,'UTF8')::jsonb;
 o control_plane.cp_operations; g control_plane.cp_generations; c control_plane.cp_continuities;
 p jsonb := e->'payload'; proposal jsonb; target text; deadline timestamptz; stamp timestamptz;
BEGIN
  PERFORM control_plane.f3_check_caller(e,caller);
  PERFORM control_plane.f3_lock_scope(e);
  SELECT * INTO o FROM control_plane.cp_operations x WHERE x.authority_domain_id=(e->>'authority_domain_id')::uuid
    AND x.operation_id=(e->>'operation_id')::uuid FOR UPDATE;
  IF NOT FOUND THEN PERFORM control_plane.f3_fail('OPERATION_MISSING'); END IF;
  IF o.request_wire IS DISTINCT FROM request_bytes OR o.creator_scope IS DISTINCT FROM caller THEN
    PERFORM control_plane.f3_fail('OPERATION_CONFLICT'); END IF;
  IF o.state IN ('COMMITTED','ABORTED') THEN
    IF o.f3_authorization_wire IS DISTINCT FROM authorization_bytes THEN
      PERFORM control_plane.f3_fail('AUTHORIZATION_CONFLICT'); END IF;
    RETURN QUERY SELECT o.operation_id,o.state::text,o.terminal_wire,true; RETURN;
  END IF;
  IF o.prepare_wire IS NULL OR o.f3_proposal IS NOT NULL THEN PERFORM control_plane.f3_fail('PROPOSAL_PENDING'); END IF;
  IF auth->>'authorization_version' IS DISTINCT FROM '1' OR coalesce(auth->>'decision','') NOT IN ('COMMIT','ABORT')
      OR auth - ARRAY['authorization_version','decision','operation_id','request_envelope_hash','local_commit_id',
        'staged_result_hash','core_audit_predecessor_hash','core_audit_candidate_hash',
        'transaction_evidence_hash','no_local_business_commit','abort_evidence_hash'] <> '{}'::jsonb
      OR (auth->>'decision'='COMMIT' AND ((SELECT count(*) FROM jsonb_object_keys(auth)) <> 9
          OR auth ? 'no_local_business_commit' OR auth ? 'abort_evidence_hash'))
      OR (auth->>'decision'='ABORT' AND ((SELECT count(*) FROM jsonb_object_keys(auth)) <> 10
          OR auth ? 'transaction_evidence_hash'))
      OR auth->>'operation_id' IS DISTINCT FROM e->>'operation_id'
      OR auth->>'request_envelope_hash' IS DISTINCT FROM o.request_envelope_hash
      OR auth->>'local_commit_id' IS DISTINCT FROM p->>'local_commit_id'
      OR auth->>'staged_result_hash' IS DISTINCT FROM o.staged_result_hash
      OR auth->>'core_audit_predecessor_hash' IS DISTINCT FROM o.core_audit_predecessor_hash
      OR auth->>'core_audit_candidate_hash' IS DISTINCT FROM o.core_audit_candidate_hash
      OR (auth->>'decision'='COMMIT' AND coalesce(auth->>'transaction_evidence_hash','') !~ '^[0-9a-f]{64}$')
      OR (auth->>'decision'='ABORT' AND (auth->'no_local_business_commit' IS DISTINCT FROM 'true'::jsonb
          OR coalesce(auth->>'abort_evidence_hash','') !~ '^[0-9a-f]{64}$')) THEN
    PERFORM control_plane.f3_fail('ATTESTATION_MISMATCH'); END IF;
  deadline := control_plane.f3_check_current(e);
  SELECT * INTO c FROM control_plane.cp_continuities WHERE authority_domain_id=o.authority_domain_id
    AND continuity_id=o.continuity_id;
  SELECT * INTO g FROM control_plane.cp_generations WHERE authority_domain_id=o.authority_domain_id
    AND authority_generation=o.authority_generation;
  target := CASE auth->>'decision' WHEN 'COMMIT' THEN 'COMMITTED' ELSE 'ABORTED' END;
  stamp := clock_timestamp();
  proposal := jsonb_build_object('receipt_version',1,'schema_version',1,
    'authority_domain_id',o.authority_domain_id::text,'authority_instance_id',o.authority_instance_id::text,
    'authority_generation',o.authority_generation,'qingyu_identity_id',o.qingyu_identity_id::text,
    'continuity_id',o.continuity_id::text,'operation_id',o.operation_id::text,'operation_type',o.operation_type,
    'request_envelope_hash',o.request_envelope_hash,'result_state',target,'result_code',target,
    'actor_or_owner_identity',o.actor_or_owner_identity,'continuity_epoch',c.continuity_epoch,
    'storage_generation_id',o.storage_generation_id::text,'control_plane_generation_id',c.control_plane_generation_id::text,
    'owner_version',c.owner_version,'lease_generation',c.lease_generation,'authority_sequence',g.authority_sequence+1,
    'previous_receipt_hash',g.head_hash,'result_payload_hash',CASE target WHEN 'COMMITTED' THEN o.staged_result_hash ELSE p->>'abort_result_hash' END,
    'staged_result_hash',o.staged_result_hash,'core_audit_predecessor_hash',o.core_audit_predecessor_hash,
    'core_audit_candidate_hash',o.core_audit_candidate_hash,
    'decided_at',to_char(stamp AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'receipt_key_id',g.receipt_key_id,'signed_provisioning_origin_digest',NULL,'previous_generation',NULL,
    'previous_generation_sequence',NULL,'previous_generation_head_hash',NULL,'signed_dr_artifact_digest',NULL);
  UPDATE control_plane.cp_operations x SET f3_proposal=proposal,f3_proposal_wire=control_plane.f3_flat_jcs(proposal),
    f3_proposal_xid=pg_current_xact_id(),f3_proposal_pid=pg_backend_pid(),f3_deadline=deadline,
    f3_authorization_wire=authorization_bytes,local_commit_attestation_hash=encode(sha256(authorization_bytes),'hex')
    WHERE x.authority_domain_id=o.authority_domain_id AND x.operation_id=o.operation_id AND x.state='PREPARED';
  RETURN QUERY SELECT o.operation_id,target,control_plane.f3_flat_jcs(proposal),false;
END;
$$;

CREATE FUNCTION control_plane.f3_lookup_intent(op_id uuid, caller jsonb) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, control_plane, pg_temp AS $$
DECLARE o control_plane.cp_operations;
BEGIN
  SELECT * INTO o FROM control_plane.cp_operations WHERE authority_domain_id=(caller->>'authority_domain_id')::uuid AND operation_id=op_id;
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF o.creator_scope IS DISTINCT FROM caller THEN PERFORM control_plane.f3_fail('OPERATION_CONFLICT'); END IF;
  IF o.prepare_wire IS NULL THEN PERFORM control_plane.f3_fail('OPERATION_MISSING'); END IF;
  RETURN o.request_wire;
END;
$$;

CREATE FUNCTION control_plane.f3_finalize_terminal(op_id uuid, signature bytea) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, control_plane, pg_temp AS $$
DECLARE o control_plane.cp_operations; proposal jsonb; result jsonb; result_wire bytea;
 target text; result_hash text; deadline timestamptz; selected_result jsonb; audit_hash text; changed bigint;
BEGIN
  SELECT * INTO o FROM control_plane.cp_operations WHERE operation_id=op_id
    AND f3_proposal_xid=pg_current_xact_id() AND f3_proposal_pid=pg_backend_pid();
  IF NOT FOUND OR o.state <> 'PREPARED' OR o.prepare_wire IS NULL
      OR o.f3_proposal->>'result_state' NOT IN ('COMMITTED','ABORTED')
      OR o.f3_proposal_wire IS DISTINCT FROM control_plane.f3_flat_jcs(o.f3_proposal)
      OR signature IS NULL OR octet_length(signature) <> 64 THEN
    PERFORM control_plane.f3_fail('PROPOSAL_MISMATCH'); END IF;
  deadline := control_plane.f3_check_current(o.request_envelope);
  proposal := o.f3_proposal; target := proposal->>'result_state';
  selected_result := o.request_envelope->'payload'->CASE target WHEN 'COMMITTED' THEN 'staged_result' ELSE 'abort_result' END;
  audit_hash := CASE target WHEN 'COMMITTED' THEN o.core_audit_candidate_hash ELSE selected_result->>'core_audit_candidate_hash' END;
  result := proposal || jsonb_build_object('receipt_signature',encode(signature,'hex'));
  result_wire := control_plane.f3_flat_jcs(result);
  result_hash := encode(sha256(convert_to('QINGYU-CP-R1-AUTHORITY-RECEIPT','UTF8') || decode('00','hex') || result_wire),'hex');
  UPDATE control_plane.cp_continuities SET state_version=state_version + CASE target WHEN 'COMMITTED' THEN 1 ELSE 0 END,
    core_audit_head_hash=audit_hash,core_audit_sequence=core_audit_sequence+1
    WHERE authority_domain_id=o.authority_domain_id AND continuity_id=o.continuity_id
      AND state_version=o.expected_state_version AND continuity_epoch=o.expected_continuity_epoch
      AND active_storage_generation_id=o.storage_generation_id AND owner_version=o.expected_owner_version
      AND core_audit_head_hash=o.core_audit_predecessor_hash;
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed <> 1 THEN PERFORM control_plane.f3_fail('FINAL_CAS'); END IF;
  UPDATE control_plane.cp_generations SET authority_sequence=(proposal->>'authority_sequence')::bigint,head_hash=result_hash
    WHERE authority_domain_id=o.authority_domain_id AND authority_generation=o.authority_generation
      AND status='ACTIVE' AND authority_instance_id=o.authority_instance_id
      AND authority_sequence=(proposal->>'authority_sequence')::bigint-1 AND head_hash=proposal->>'previous_receipt_hash';
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed <> 1 THEN PERFORM control_plane.f3_fail('HEAD_CAS'); END IF;
  UPDATE control_plane.cp_operations SET state=target,result_code=target,result_payload=selected_result,
    result_payload_hash=proposal->>'result_payload_hash',continuity_epoch=(proposal->>'continuity_epoch')::bigint,
    control_plane_generation_id=(proposal->>'control_plane_generation_id')::uuid,
    owner_version=(proposal->>'owner_version')::bigint,lease_generation=(proposal->>'lease_generation')::bigint,
    receipt_key_id=proposal->>'receipt_key_id',authority_sequence=(proposal->>'authority_sequence')::bigint,
    previous_receipt_hash=proposal->>'previous_receipt_hash',receipt_hash=result_hash,receipt_payload=result,
    receipt_signature=signature,decided_at=(proposal->>'decided_at')::timestamptz,terminal_wire=result_wire,
    f3_proposal=NULL,f3_proposal_wire=NULL,f3_proposal_xid=NULL,f3_proposal_pid=NULL,
    f3_finalized_xid=pg_current_xact_id(),f3_deadline=least(o.f3_deadline,deadline)
    WHERE authority_domain_id=o.authority_domain_id AND operation_id=o.operation_id AND state='PREPARED';
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed <> 1 THEN PERFORM control_plane.f3_fail('TERMINAL_CAS'); END IF;
  RETURN result_wire;
END;
$$;

CREATE FUNCTION control_plane.f3_query(op_id uuid, caller jsonb, expected_hash text DEFAULT NULL)
RETURNS TABLE(state text, wire bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, control_plane, pg_temp AS $$
DECLARE o control_plane.cp_operations;
BEGIN
  SELECT * INTO o FROM control_plane.cp_operations WHERE authority_domain_id=(caller->>'authority_domain_id')::uuid AND operation_id=op_id;
  IF NOT FOUND THEN RETURN; END IF;
  IF o.creator_scope IS DISTINCT FROM caller OR (expected_hash IS NOT NULL AND expected_hash <> o.request_envelope_hash) THEN
    PERFORM control_plane.f3_fail('OPERATION_CONFLICT'); END IF;
  IF o.prepare_wire IS NULL THEN PERFORM control_plane.f3_fail('OPERATION_MISSING'); END IF;
  RETURN QUERY SELECT o.state::text,coalesce(o.terminal_wire,o.prepare_wire);
END;
$$;

CREATE VIEW control_plane.f3_runtime_description AS
SELECT '__F3_DIGEST__'::text AS f3_contract_digest, 1 AS f3_contract_version,
 o.authority_domain_id,o.provisioning_uuid,o.operator_root_key_id,o.cluster_system_identifier,
 o.cluster_binding_fingerprint,o.database_name,o.signed_provisioning_origin_digest,
 g.authority_instance_id,g.authority_generation,g.receipt_key_id,g.status AS generation_status,
 k.public_key AS receipt_public_key,k.revoked_at AS receipt_key_revoked_at
FROM control_plane.cp_origin o JOIN control_plane.cp_generations g USING (authority_domain_id)
JOIN control_plane.cp_receipt_keys k ON k.authority_domain_id=g.authority_domain_id AND k.receipt_key_id=g.receipt_key_id
WHERE g.status='ACTIVE';

CREATE FUNCTION control_plane.f3_genesis_evidence(caller jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, control_plane, pg_temp AS $$
DECLARE c control_plane.cp_continuities; g control_plane.cp_operations;
BEGIN
  SELECT * INTO c FROM control_plane.cp_continuities WHERE authority_domain_id=(caller->>'authority_domain_id')::uuid
    AND continuity_id=(caller->>'continuity_id')::uuid;
  IF NOT FOUND OR c.owner_identity IS DISTINCT FROM caller->>'actor_identity' THEN
    PERFORM control_plane.f3_fail('CALLER_SCOPE'); END IF;
  SELECT * INTO g FROM control_plane.cp_operations WHERE authority_domain_id=c.authority_domain_id
    AND operation_id=c.genesis_operation_id AND continuity_id=c.continuity_id AND qingyu_identity_id=c.qingyu_identity_id;
  IF NOT FOUND OR g.state <> 'COMMITTED' OR g.operation_type <> 'AUTHORITY_GENESIS_ACTIVATION' THEN
    PERFORM control_plane.f3_fail('GENESIS_FENCED'); END IF;
  RETURN jsonb_build_object('operation_id',g.operation_id::text,'request_envelope',g.request_envelope,
    'prepare_ack',g.prepare_ack,'receipt_payload',g.receipt_payload,'receipt_hash',g.receipt_hash,
    'request_envelope_hash',g.request_envelope_hash,'staged_result_hash',g.staged_result_hash,
    'core_audit_predecessor_hash',g.core_audit_predecessor_hash,'core_audit_candidate_hash',g.core_audit_candidate_hash,
    'genesis_operation_id',c.genesis_operation_id::text,'qingyu_identity_id',c.qingyu_identity_id::text,
    'continuity_id',c.continuity_id::text);
END;
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_plane FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA control_plane FROM PUBLIC,control_plane_app,control_plane_reader;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA control_plane FROM PUBLIC,control_plane_app,control_plane_reader;
GRANT USAGE ON SCHEMA control_plane TO control_plane_app,control_plane_reader;
GRANT SELECT ON control_plane.f3_runtime_description TO control_plane_app,control_plane_reader;
GRANT EXECUTE ON FUNCTION control_plane.f3_propose_prepare(bytea,jsonb,bytea,bytea),
 control_plane.f3_finalize_prepare(uuid,bytea),control_plane.f3_propose_terminal(bytea,jsonb,bytea),
 control_plane.f3_finalize_terminal(uuid,bytea),control_plane.f3_query(uuid,jsonb,text),
 control_plane.f3_lookup_intent(uuid,jsonb),control_plane.f3_genesis_evidence(jsonb) TO control_plane_app;
