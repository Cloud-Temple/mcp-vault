-- Optional #846 extension, explicit owner installation. No runtime DDL.
ALTER TABLE vault_metadata.schema_version DROP CONSTRAINT schema_version_version_check;
ALTER TABLE vault_metadata.schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=3) NOT VALID;
UPDATE vault_metadata.schema_version SET version=3 WHERE version=2;
ALTER TABLE vault_metadata.schema_version VALIDATE CONSTRAINT schema_version_version_check;

CREATE TABLE vault_metadata.audit_mission_holds (
 instance_id text NOT NULL REFERENCES vault_metadata.audit_retention_policy,
 tenant_id text NOT NULL, mission_id text NOT NULL,
 claim_id uuid, closure_revision bigint, terminal_at timestamptz,
 retain_until timestamptz, proof_sha256 text,
 PRIMARY KEY(instance_id,tenant_id,mission_id),
 CHECK(instance_id<>'' AND tenant_id<>'' AND mission_id<>''),
 CHECK((claim_id IS NULL AND closure_revision IS NULL AND terminal_at IS NULL
        AND retain_until IS NULL AND proof_sha256 IS NULL)
   OR (claim_id IS NOT NULL AND closure_revision IS NOT NULL AND closure_revision>0 AND terminal_at IS NOT NULL
       AND retain_until IS NOT NULL AND retain_until>=terminal_at+interval '365 days'
       AND proof_sha256 IS NOT NULL AND proof_sha256 ~ '^[a-f0-9]{64}$'))
);

-- Existing correlations become protected, never silently standalone.
INSERT INTO vault_metadata.audit_mission_holds(instance_id,tenant_id,mission_id)
 SELECT DISTINCT instance_id,tenant_id,mission_id FROM vault_metadata.audit_calls
 WHERE tenant_id IS NOT NULL AND tenant_id<>'' AND mission_id IS NOT NULL AND mission_id<>'';

CREATE OR REPLACE FUNCTION vault_metadata.audit_fill_call() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE days integer;
BEGIN
 SELECT retention_days INTO STRICT days FROM vault_metadata.audit_retention_policy WHERE instance_id=NEW.instance_id;
 IF NEW.mission_id IS NOT NULL AND NEW.mission_id<>'' AND NEW.tenant_id IS NOT NULL AND NEW.tenant_id<>'' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(NEW.instance_id,NEW.tenant_id,NEW.mission_id)::text,846));
  INSERT INTO vault_metadata.audit_mission_holds(instance_id,tenant_id,mission_id)
   VALUES(NEW.instance_id,NEW.tenant_id,NEW.mission_id) ON CONFLICT DO NOTHING;
  IF EXISTS(SELECT 1 FROM vault_metadata.audit_mission_holds
    WHERE (instance_id,tenant_id,mission_id)=(NEW.instance_id,NEW.tenant_id,NEW.mission_id)
    AND claim_id IS NOT NULL) THEN
   RAISE EXCEPTION 'closed mission audit correlation' USING ERRCODE='42501';
  END IF;
 END IF;
 NEW.created_at:=clock_timestamp();
 NEW.expires_at:=NEW.created_at+make_interval(days=>days);
 RETURN NEW;
END $$;

CREATE FUNCTION vault_metadata.audit_retention_expired(wanted_instance text, wanted_tenant text, wanted_mission text)
RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT wanted_mission IS NULL OR EXISTS(
  SELECT 1 FROM vault_metadata.audit_mission_holds
  WHERE (instance_id,tenant_id,mission_id)=(wanted_instance,wanted_tenant,wanted_mission)
   AND claim_id IS NOT NULL AND retain_until<=clock_timestamp());
$$;

CREATE FUNCTION vault_metadata.audit_close_mission(wanted_instance text, wanted_tenant text, wanted_mission text,
 wanted_claim uuid, wanted_revision bigint, wanted_terminal timestamptz, wanted_until timestamptz, wanted_proof text,
 authority_expires timestamptz)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE held vault_metadata.audit_mission_holds; stamp timestamptz;
BEGIN
 IF wanted_claim IS NULL OR wanted_revision IS NULL OR wanted_revision<1
  OR wanted_terminal IS NULL OR wanted_until IS NULL OR wanted_proof IS NULL OR authority_expires IS NULL
  OR wanted_proof !~ '^[a-f0-9]{64}$' OR wanted_until<wanted_terminal+interval '365 days' THEN
  RAISE EXCEPTION 'invalid mission retention closure';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(wanted_instance,wanted_tenant,wanted_mission)::text,846));
 SELECT * INTO STRICT held FROM vault_metadata.audit_mission_holds
  WHERE (instance_id,tenant_id,mission_id)=(wanted_instance,wanted_tenant,wanted_mission) FOR UPDATE;
 -- Fresh PG clock after the potentially blocking scope/row locks.
 stamp:=clock_timestamp();
 IF authority_expires<=stamp OR authority_expires>stamp+interval '30 seconds'
  OR wanted_terminal>stamp OR (held.claim_id IS NOT NULL AND
  (held.claim_id,held.closure_revision,held.terminal_at,held.retain_until,held.proof_sha256)
   IS DISTINCT FROM (wanted_claim,wanted_revision,wanted_terminal,wanted_until,wanted_proof)) THEN
  RAISE EXCEPTION 'conflicting mission retention closure';
 END IF;
 UPDATE vault_metadata.audit_mission_holds SET claim_id=wanted_claim,closure_revision=wanted_revision,
  terminal_at=wanted_terminal,retain_until=wanted_until,proof_sha256=wanted_proof
  WHERE (instance_id,tenant_id,mission_id)=(wanted_instance,wanted_tenant,wanted_mission);
 RETURN true;
END $$;

CREATE FUNCTION vault_metadata.audit_mission_status(wanted_instance text, wanted_tenant text, wanted_mission text)
RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('known',h.instance_id IS NOT NULL,'claim_id',h.claim_id,
  'closure_revision',h.closure_revision,'terminal_at',h.terminal_at,'retain_until',h.retain_until,
  'remaining_calls',(SELECT count(*) FROM vault_metadata.audit_calls c
   WHERE (c.instance_id,c.tenant_id,c.mission_id)=(wanted_instance,wanted_tenant,wanted_mission)),
  'retention_elapsed',coalesce(h.claim_id IS NOT NULL AND h.retain_until<=clock_timestamp(),false))
 FROM (SELECT 1) singleton LEFT JOIN vault_metadata.audit_mission_holds h
 ON (h.instance_id,h.tenant_id,h.mission_id)=(wanted_instance,wanted_tenant,wanted_mission);
$$;

CREATE FUNCTION vault_metadata.audit_expire_bound(wanted_instance text, wanted_tenant text, wanted_mission text,
 batch integer, dry_run boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidates uuid[]; ids uuid[]; scoped record; call_count integer; event_count integer; more boolean; receipt uuid;
BEGIN
 IF batch IS NULL OR batch<1 OR batch>500 OR dry_run IS NULL
  OR (wanted_tenant IS NULL)<>(wanted_mission IS NULL) OR wanted_tenant='' OR wanted_mission='' THEN
  RAISE EXCEPTION 'invalid audit expiry request';
 END IF;
 SELECT array_agg(call_id) INTO candidates FROM (
  SELECT call_id FROM vault_metadata.audit_calls
  WHERE instance_id=wanted_instance AND expires_at<=clock_timestamp()
   AND (wanted_mission IS NULL OR (tenant_id,mission_id)=(wanted_tenant,wanted_mission))
   AND vault_metadata.audit_retention_expired(instance_id,tenant_id,mission_id)
  ORDER BY expires_at,call_id LIMIT batch) selected;
 candidates:=coalesce(candidates,ARRAY[]::uuid[]);
 -- Same stable scope-before-call order as admission and closure, bounded by batch.
 FOR scoped IN SELECT DISTINCT tenant_id,mission_id FROM vault_metadata.audit_calls
  WHERE instance_id=wanted_instance AND call_id=ANY(candidates) AND mission_id IS NOT NULL
  ORDER BY tenant_id,mission_id LOOP
  PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(wanted_instance,scoped.tenant_id,scoped.mission_id)::text,846));
 END LOOP;
 SELECT array_agg(call_id) INTO ids FROM (
  SELECT call_id FROM vault_metadata.audit_calls
  WHERE instance_id=wanted_instance AND call_id=ANY(candidates) AND expires_at<=clock_timestamp()
   AND vault_metadata.audit_retention_expired(instance_id,tenant_id,mission_id)
  ORDER BY expires_at,call_id FOR UPDATE SKIP LOCKED) selected;
 ids:=coalesce(ids,ARRAY[]::uuid[]);
 call_count:=cardinality(ids);
 SELECT count(*) INTO event_count FROM vault_metadata.audit_events
  WHERE instance_id=wanted_instance AND call_id=ANY(ids);
 IF NOT dry_run AND call_count>0 THEN
  DELETE FROM vault_metadata.audit_events WHERE instance_id=wanted_instance AND call_id=ANY(ids);
  DELETE FROM vault_metadata.audit_calls WHERE instance_id=wanted_instance AND call_id=ANY(ids);
  receipt:=gen_random_uuid();
  INSERT INTO vault_metadata.audit_calls(instance_id,call_id,actor_ref,tool)
   VALUES(wanted_instance,receipt,'operator_'||substr(md5(session_user),1,16),'audit_expire');
  INSERT INTO vault_metadata.audit_events(instance_id,call_id,phase,step_id,outcome)
   VALUES(wanted_instance,receipt,'public_terminal','00000000-0000-0000-0000-000000000000','completed');
 END IF;
 SELECT EXISTS(SELECT 1 FROM vault_metadata.audit_calls
  WHERE instance_id=wanted_instance AND expires_at<=clock_timestamp()
  AND (wanted_mission IS NULL OR (tenant_id,mission_id)=(wanted_tenant,wanted_mission))
  AND vault_metadata.audit_retention_expired(instance_id,tenant_id,mission_id)
  AND NOT(call_id=ANY(ids))) INTO more;
 RETURN jsonb_build_object('calls',call_count,'events',event_count,'dry_run',dry_run,'has_more',more,'receipt',receipt);
END $$;
CREATE OR REPLACE FUNCTION vault_metadata.audit_expire(wanted_instance text, batch integer, dry_run boolean)
RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT vault_metadata.audit_expire_bound(wanted_instance,NULL,NULL,batch,dry_run);
$$;
REVOKE ALL ON TABLE vault_metadata.audit_mission_holds FROM PUBLIC;
REVOKE ALL ON FUNCTION vault_metadata.audit_retention_expired(text,text,text),
 vault_metadata.audit_close_mission(text,text,text,uuid,bigint,timestamptz,timestamptz,text,timestamptz),
 vault_metadata.audit_mission_status(text,text,text),vault_metadata.audit_expire_bound(text,text,text,integer,boolean) FROM PUBLIC;
