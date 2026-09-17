-- Explicit isolated scoped-V2 candidate, never an automatic production migration.
CREATE TABLE control_plane.r1s_scopes (
 scope_id uuid PRIMARY KEY, configuration_digest text NOT NULL CHECK(configuration_digest ~ '^[0-9a-f]{64}$'),
 revision bigint NOT NULL DEFAULT 0 CHECK(revision >= 0),
 deadline_ms bigint, changed_xid xid8
);
CREATE TABLE control_plane.r1s_journal (
 scope_id uuid NOT NULL REFERENCES control_plane.r1s_scopes(scope_id),
 revision bigint NOT NULL CHECK(revision > 0), window_wire bytea NOT NULL,
 PRIMARY KEY(scope_id,revision)
);
CREATE TABLE control_plane.r1s_operations (
 scope_id uuid NOT NULL REFERENCES control_plane.r1s_scopes(scope_id), operation_id uuid NOT NULL,
 request_wire bytea NOT NULL, source_wire bytea NOT NULL,
 ack_wire bytea, authorization_wire bytea, proposal_wire bytea, acceptance_wire bytea,
 publication_wire bytea, terminal_wire bytea,
 PRIMARY KEY(scope_id,operation_id),
 CHECK ((acceptance_wire IS NULL) = (proposal_wire IS NULL)),
 CHECK ((acceptance_wire IS NULL) = (authorization_wire IS NULL)),
 CHECK (acceptance_wire IS NULL OR ack_wire IS NOT NULL),
 CHECK (terminal_wire IS NULL OR (acceptance_wire IS NOT NULL AND publication_wire IS NOT NULL))
);
CREATE FUNCTION control_plane.r1s_fail(code text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,control_plane,pg_temp AS $$
BEGIN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='R1_F3_' || code; END $$;
CREATE FUNCTION control_plane.r1s_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,control_plane,pg_temp AS $$
BEGIN
 IF TG_TABLE_NAME='r1s_journal' OR TG_OP='DELETE' THEN PERFORM control_plane.r1s_fail('IMMUTABLE_HISTORY'); END IF;
 IF OLD.scope_id IS DISTINCT FROM NEW.scope_id OR OLD.operation_id IS DISTINCT FROM NEW.operation_id
  OR OLD.request_wire IS DISTINCT FROM NEW.request_wire OR OLD.source_wire IS DISTINCT FROM NEW.source_wire
  OR (OLD.ack_wire IS NOT NULL AND OLD.ack_wire IS DISTINCT FROM NEW.ack_wire)
  OR (OLD.authorization_wire IS NOT NULL AND OLD.authorization_wire IS DISTINCT FROM NEW.authorization_wire)
  OR (OLD.proposal_wire IS NOT NULL AND OLD.proposal_wire IS DISTINCT FROM NEW.proposal_wire)
  OR (OLD.acceptance_wire IS NOT NULL AND OLD.acceptance_wire IS DISTINCT FROM NEW.acceptance_wire)
  OR (OLD.publication_wire IS NOT NULL AND OLD.publication_wire IS DISTINCT FROM NEW.publication_wire)
  OR (OLD.terminal_wire IS NOT NULL AND OLD.terminal_wire IS DISTINCT FROM NEW.terminal_wire)
 THEN PERFORM control_plane.r1s_fail('IMMUTABLE_HISTORY'); END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER r1s_journal_immutable BEFORE UPDATE OR DELETE ON control_plane.r1s_journal
 FOR EACH ROW EXECUTE FUNCTION control_plane.r1s_immutable();
CREATE TRIGGER r1s_operation_immutable BEFORE UPDATE OR DELETE ON control_plane.r1s_operations
 FOR EACH ROW EXECUTE FUNCTION control_plane.r1s_immutable();
CREATE FUNCTION control_plane.r1s_deadline_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,control_plane,pg_temp AS $$
DECLARE s control_plane.r1s_scopes;
BEGIN
 SELECT * INTO s FROM control_plane.r1s_scopes WHERE scope_id=NEW.scope_id;
 IF s.changed_xid=pg_current_xact_id() AND s.deadline_ms IS NOT NULL
  AND floor(extract(epoch FROM clock_timestamp())*1000)::bigint >= s.deadline_ms
 THEN PERFORM control_plane.r1s_fail('COMMIT_EXPIRED'); END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER r1s_final_deadline AFTER UPDATE ON control_plane.r1s_scopes
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION control_plane.r1s_deadline_guard();

-- Every governance ingestion and operation action takes this same row lock.
-- The full trusted qualification journal cannot change during Python replay,
-- signing, semantic validation or final persistence, including across processes.
CREATE FUNCTION control_plane.r1s_lock(sid uuid, expected_configuration text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,control_plane,pg_temp AS $$
DECLARE s control_plane.r1s_scopes;
BEGIN
 SELECT * INTO s FROM control_plane.r1s_scopes WHERE scope_id=sid FOR UPDATE;
 IF NOT FOUND OR s.configuration_digest IS DISTINCT FROM expected_configuration
 THEN PERFORM control_plane.r1s_fail('SCOPED_CONFIGURATION_FENCED'); END IF;
 RETURN s.revision;
END $$;
CREATE FUNCTION control_plane.r1s_history(sid uuid)
RETURNS TABLE(revision bigint,window_wire bytea)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,control_plane,pg_temp AS $$
 SELECT j.revision,j.window_wire FROM control_plane.r1s_journal j WHERE j.scope_id=sid ORDER BY j.revision
$$;
CREATE FUNCTION control_plane.r1s_operation(sid uuid,op uuid)
RETURNS SETOF control_plane.r1s_operations
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,control_plane,pg_temp AS $$
 SELECT o.* FROM control_plane.r1s_operations o WHERE o.scope_id=sid AND o.operation_id=op
$$;
CREATE FUNCTION control_plane.r1s_append(sid uuid,expected_revision bigint,body bytea,deadline bigint,
 op uuid DEFAULT NULL,request_bytes bytea DEFAULT NULL,source_bytes bytea DEFAULT NULL,
 ack bytea DEFAULT NULL,authorization_bytes bytea DEFAULT NULL,proposal bytea DEFAULT NULL,
 acceptance bytea DEFAULT NULL,publication bytea DEFAULT NULL,terminal bytea DEFAULT NULL)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,control_plane,pg_temp AS $$
DECLARE s control_plane.r1s_scopes; o control_plane.r1s_operations;
BEGIN
 SELECT * INTO s FROM control_plane.r1s_scopes WHERE scope_id=sid FOR UPDATE;
 IF NOT FOUND OR s.revision<>expected_revision THEN PERFORM control_plane.r1s_fail('TRANSACTION_CONFLICT'); END IF;
 IF body IS NULL OR octet_length(body)=0 OR octet_length(body)>33554432
 THEN PERFORM control_plane.r1s_fail('WINDOW_SHAPE'); END IF;
 IF deadline IS NOT NULL AND floor(extract(epoch FROM clock_timestamp())*1000)::bigint>=deadline
 THEN PERFORM control_plane.r1s_fail('COMMIT_EXPIRED'); END IF;
 IF op IS NOT NULL THEN
  IF request_bytes IS NULL OR source_bytes IS NULL THEN PERFORM control_plane.r1s_fail('INTENT_SHAPE'); END IF;
  SELECT * INTO o FROM control_plane.r1s_operations WHERE scope_id=sid AND operation_id=op FOR UPDATE;
  IF FOUND THEN
   IF o.request_wire IS DISTINCT FROM request_bytes OR o.source_wire IS DISTINCT FROM source_bytes
   THEN PERFORM control_plane.r1s_fail('OPERATION_CONFLICT'); END IF;
   UPDATE control_plane.r1s_operations SET ack_wire=coalesce(ack,o.ack_wire),
    authorization_wire=coalesce(authorization_bytes,o.authorization_wire),proposal_wire=coalesce(proposal,o.proposal_wire),
    acceptance_wire=coalesce(acceptance,o.acceptance_wire),publication_wire=coalesce(publication,o.publication_wire),
    terminal_wire=coalesce(terminal,o.terminal_wire) WHERE scope_id=sid AND operation_id=op;
  ELSE
   INSERT INTO control_plane.r1s_operations VALUES(sid,op,request_bytes,source_bytes,ack,authorization_bytes,proposal,acceptance,publication,terminal);
  END IF;
 END IF;
 INSERT INTO control_plane.r1s_journal VALUES(sid,expected_revision+1,body);
 UPDATE control_plane.r1s_scopes SET revision=expected_revision+1,deadline_ms=deadline,changed_xid=pg_current_xact_id() WHERE scope_id=sid;
 RETURN expected_revision+1;
END $$;
REVOKE ALL ON control_plane.r1s_scopes,control_plane.r1s_journal,control_plane.r1s_operations FROM PUBLIC,control_plane_app,control_plane_reader;
REVOKE ALL ON FUNCTION control_plane.r1s_fail(text),control_plane.r1s_immutable(),control_plane.r1s_deadline_guard(),
 control_plane.r1s_lock(uuid,text),control_plane.r1s_history(uuid),control_plane.r1s_operation(uuid,uuid),
 control_plane.r1s_append(uuid,bigint,bytea,bigint,uuid,bytea,bytea,bytea,bytea,bytea,bytea,bytea,bytea) FROM PUBLIC;
GRANT USAGE ON SCHEMA control_plane TO control_plane_app;
GRANT EXECUTE ON FUNCTION control_plane.r1s_lock(uuid,text),control_plane.r1s_history(uuid),control_plane.r1s_operation(uuid,uuid),
 control_plane.r1s_append(uuid,bigint,bytea,bigint,uuid,bytea,bytea,bytea,bytea,bytea,bytea,bytea,bytea) TO control_plane_app;
