-- Explicit optional v3 -> v4 owner migration. No OpenBao or runtime DDL.
ALTER TABLE vault_metadata.schema_version DROP CONSTRAINT schema_version_version_check;
ALTER TABLE vault_metadata.schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=4) NOT VALID;
UPDATE vault_metadata.schema_version SET version=4 WHERE version=3;
ALTER TABLE vault_metadata.schema_version VALIDATE CONSTRAINT schema_version_version_check;
CREATE TABLE vault_metadata.audit_mission_retirements (
 instance_id text NOT NULL, operation_id uuid NOT NULL, tenant_id text NOT NULL, mission_id text NOT NULL,
 identity jsonb NOT NULL, proof_sha256 text NOT NULL CHECK(proof_sha256 ~ '^[a-f0-9]{64}$'),
 inventory jsonb NOT NULL CHECK(jsonb_typeof(inventory)='array' AND jsonb_array_length(inventory)<=100000
  AND octet_length(inventory::text)<=16777216),
 state text NOT NULL CHECK(state IN ('prepared','committed')),
 lots jsonb NOT NULL DEFAULT '[]'::jsonb CHECK(jsonb_typeof(lots)='array'),
 result jsonb, committed_at timestamptz, receipt_retain_until timestamptz,
 PRIMARY KEY(instance_id,operation_id), UNIQUE(instance_id,tenant_id,mission_id),
 FOREIGN KEY(instance_id,tenant_id,mission_id) REFERENCES vault_metadata.audit_mission_holds,
 CHECK(identity->>'tenant_id'=tenant_id AND identity->>'mission_id'=mission_id AND identity->>'owner'='vault'),
 CHECK((state='prepared' AND result IS NULL AND committed_at IS NULL AND receipt_retain_until IS NULL)
 OR (state='committed' AND result IS NOT NULL AND committed_at IS NOT NULL
 AND receipt_retain_until>=committed_at+interval '365 days'))
);

-- Hash the exact compact JSON encoding also used by the existing v3 closure.
-- Parsing back to ident binds every field, including non-ASCII escaped values.
CREATE FUNCTION vault_metadata.audit_retirement_identity_hash(canonical text)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT encode(sha256(convert_to(canonical,'UTF8')),'hex');
$$;

-- Acquire ALL local row locks before the controller's final live callback.
-- No audit_revision UPDATE, security mutation or DELETE before that callback.
CREATE FUNCTION vault_metadata.audit_retirement_lock(i text,t text,m text,op uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF i IS NULL OR t IS NULL OR m IS NULL OR i='' OR t='' OR m='' OR op IS NULL THEN
  RAISE EXCEPTION 'invalid retirement scope';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(i,t,m)::text,846));
 PERFORM 1 FROM vault_metadata.audit_mission_holds WHERE (instance_id,tenant_id,mission_id)=(i,t,m) FOR UPDATE;
 PERFORM 1 FROM vault_metadata.audit_mission_retirements WHERE instance_id=i AND operation_id=op FOR UPDATE;
 PERFORM 1 FROM vault_metadata.mission_bindings WHERE instance_id=i AND tenant_id=t FOR SHARE;
 PERFORM 1 FROM vault_metadata.wrap_registry WHERE instance_id=i AND mission_id=m ORDER BY operation_id FOR UPDATE;
 PERFORM 1 FROM vault_metadata.audit_calls WHERE (instance_id,tenant_id,mission_id)=(i,t,m) ORDER BY call_id FOR UPDATE;
END $$;

CREATE FUNCTION vault_metadata.audit_retirement_inventory(i text,t text,m text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE refs jsonb; w record;
BEGIN
 IF EXISTS(SELECT 1 FROM vault_metadata.audit_calls c WHERE (c.instance_id,c.tenant_id,c.mission_id)=(i,t,m)
 AND (NOT EXISTS(SELECT 1 FROM vault_metadata.audit_events e WHERE (e.instance_id,e.call_id)=(i,c.call_id)
 AND e.phase='public_terminal' AND e.outcome IN ('completed','failed','denied'))
 OR EXISTS(SELECT 1 FROM vault_metadata.audit_events e WHERE (e.instance_id,e.call_id)=(i,c.call_id)
 AND e.outcome='unknown'))) THEN RAISE EXCEPTION 'audit outcome protected'; END IF;
 FOR w IN SELECT * FROM vault_metadata.wrap_registry WHERE instance_id=i AND mission_id=m LOOP
  IF w.payload->>'tenant_id' IS DISTINCT FROM t OR w.status NOT IN ('consumed','revoked')
   OR NOT EXISTS(SELECT 1 FROM vault_metadata.operation_receipts r,
    LATERAL jsonb_array_elements(coalesce(r.target->'result_revisions','[]'::jsonb)) v
    WHERE r.instance_id=i AND r.database_result='committed'
    AND r.kind IN ('wrap:mark_consumed','wrap:mark_entries_revoked','wrap:mark_revoked')
    AND r.target->>'effect_changed'='true'
    AND v->0=jsonb_build_array(w.operation_id,w.mission_id) AND (v->>1)::bigint=w.revision)
  THEN RAISE EXCEPTION 'wrap outcome protected'; END IF;
 END LOOP;
 SELECT coalesce(jsonb_agg(ref ORDER BY ref->>'kind',ref->>'id'),'[]'::jsonb) INTO refs FROM (
  SELECT jsonb_build_object('kind','audit_call','id',call_id::text,'revision',0,'root_agent_id','') ref
   FROM vault_metadata.audit_calls WHERE (instance_id,tenant_id,mission_id)=(i,t,m)
  UNION ALL SELECT jsonb_build_object('kind','audit_event','id',e.call_id::text||':'||e.seq::text,'revision',0,'root_agent_id','')
   FROM vault_metadata.audit_events e JOIN vault_metadata.audit_calls c USING(instance_id,call_id)
   WHERE (c.instance_id,c.tenant_id,c.mission_id)=(i,t,m)
  UNION ALL SELECT jsonb_build_object('kind','binding_reference','id',tenant_id,'revision',revision,'root_agent_id','')
   FROM vault_metadata.mission_bindings WHERE instance_id=i AND tenant_id=t
  UNION ALL SELECT jsonb_build_object('kind','wrap_reference','id',operation_id||':'||mission_id,'revision',revision,'root_agent_id','')
   FROM vault_metadata.wrap_registry WHERE instance_id=i AND mission_id=m) x;
 IF jsonb_array_length(refs)>100000 OR octet_length(refs::text)>16777216
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(refs) v WHERE octet_length(v->>'id')>256) THEN
  RAISE EXCEPTION 'retirement inventory incomplete'; END IF;
 RETURN refs;
END $$;

-- v3 closure plus hold creation; same signature, owner and ACL (v3 verify
-- reads this body first once v4 is installed).
CREATE OR REPLACE FUNCTION vault_metadata.audit_close_mission(wanted_instance text, wanted_tenant text, wanted_mission text,
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
 -- A Mission that never called Vault has no hold yet. Closing creates it under
 -- the admission lock, so audit_fill_call/audit_wrap_admit refuse any later
 -- correlation: that closure, not an empty observation, proves zero activity.
 INSERT INTO vault_metadata.audit_mission_holds(instance_id,tenant_id,mission_id)
  VALUES(wanted_instance,wanted_tenant,wanted_mission) ON CONFLICT DO NOTHING;
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

-- The stored inventory stays exhaustive. Mission budgets 1000 references for
-- all owners, so its receipt carries one fixed reference per source kind:
-- id = sha256 of the jsonb text of the sorted (COLLATE "C") "id@revision"
-- items, revision = item count. An unknown kind is refused, never dropped.
CREATE FUNCTION vault_metadata.audit_retirement_references(inventory jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE refs jsonb;
BEGIN
 IF jsonb_typeof(inventory) IS DISTINCT FROM 'array' OR EXISTS(SELECT 1 FROM jsonb_array_elements(inventory) v
  WHERE v->>'kind' IS NULL OR v->>'kind' NOT IN ('audit_call','audit_event','binding_reference','wrap_reference')
  OR v->>'id' IS NULL OR jsonb_typeof(v->'revision') IS DISTINCT FROM 'number') THEN
  RAISE EXCEPTION 'retirement inventory incomplete'; END IF;
 SELECT jsonb_agg(jsonb_build_object('kind',g.kind,
   'id','sha256:'||encode(sha256(convert_to(coalesce((SELECT jsonb_agg(x.item ORDER BY x.item COLLATE "C")
    FROM (SELECT (v->>'id')||'@'||(v->>'revision') AS item FROM jsonb_array_elements(inventory) v
    WHERE v->>'kind'=g.source) x),'[]'::jsonb)::text,'UTF8')),'hex'),
   'revision',(SELECT count(*) FROM jsonb_array_elements(inventory) v WHERE v->>'kind'=g.source),
   'root_agent_id','') ORDER BY g.kind COLLATE "C") INTO refs
 FROM (VALUES('vault_audit_calls','audit_call'),('vault_audit_events','audit_event'),
  ('vault_binding_references','binding_reference'),('vault_wrap_references','wrap_reference')) g(kind,source);
 RETURN refs;
END $$;

CREATE FUNCTION vault_metadata.audit_retirement_prepare(i text, ident jsonb, op uuid, canonical text, expires timestamptz)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE h vault_metadata.audit_mission_holds; r vault_metadata.audit_mission_retirements; refs jsonb;
 t text:=ident->>'tenant_id'; m text:=ident->>'mission_id'; stamp timestamptz;
 fingerprint text:=vault_metadata.audit_retirement_identity_hash(canonical);
BEGIN
 PERFORM vault_metadata.audit_retirement_lock(i,t,m,op);
 SELECT * INTO STRICT h FROM vault_metadata.audit_mission_holds WHERE (instance_id,tenant_id,mission_id)=(i,t,m);
 stamp:=clock_timestamp();
 IF jsonb_typeof(ident)<>'object' OR
 (SELECT array_agg(key ORDER BY key COLLATE "C") FROM jsonb_object_keys(ident) key)
 IS DISTINCT FROM ARRAY['claim_id','claim_revision','manifest_sha256','mission_id','owner','retain_until','root_agent_id','tenant_id','terminal_at']::text[]
 OR canonical::jsonb IS DISTINCT FROM ident
 OR ident->>'owner' IS DISTINCT FROM 'vault' THEN
  RAISE EXCEPTION 'retirement identity mismatch'; END IF;
 IF expires IS NULL OR expires<=stamp OR expires>stamp+interval '30 seconds' OR h.claim_id IS NULL
 OR (h.claim_id::text,h.closure_revision,h.terminal_at,h.retain_until,h.proof_sha256)
 IS DISTINCT FROM (ident->>'claim_id',(ident->>'claim_revision')::bigint,(ident->>'terminal_at')::timestamptz,
 (ident->>'retain_until')::timestamptz,fingerprint) OR h.retain_until>stamp THEN
  RAISE EXCEPTION 'retirement closure protected'; END IF;
 SELECT * INTO r FROM vault_metadata.audit_mission_retirements WHERE instance_id=i AND operation_id=op;
 IF FOUND THEN
  IF r.identity IS DISTINCT FROM ident OR r.proof_sha256 IS DISTINCT FROM fingerprint THEN
   RAISE EXCEPTION 'retirement operation mismatch'; END IF;
  RETURN jsonb_build_object('state',r.state,'inventory',vault_metadata.audit_retirement_references(r.inventory),'lots',r.lots);
 END IF;
 refs:=vault_metadata.audit_retirement_inventory(i,t,m);
 -- The closed hold checked above is the proof: no correlated call or wrap can
 -- be admitted after closure, so an empty inventory here is a real zero.
 INSERT INTO vault_metadata.audit_mission_retirements(instance_id,operation_id,tenant_id,mission_id,identity,proof_sha256,inventory,state)
 VALUES(i,op,t,m,ident,fingerprint,refs,'prepared');
 RETURN jsonb_build_object('state','prepared','inventory',vault_metadata.audit_retirement_references(refs),'lots','[]'::jsonb);
END $$;

CREATE FUNCTION vault_metadata.audit_retirement_batch(i text,ident jsonb,op uuid,canonical text,expires timestamptz,batch integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r vault_metadata.audit_mission_retirements; refs jsonb; expected jsonb; ids uuid[]; removed uuid[];
 events text[]; receipt uuid; more boolean; envelope jsonb; stamp timestamptz;
 t text:=ident->>'tenant_id'; m text:=ident->>'mission_id';
BEGIN
 IF batch IS NULL OR batch<1 OR batch>500 THEN RAISE EXCEPTION 'invalid batch'; END IF;
 PERFORM vault_metadata.audit_retirement_prepare(i,ident,op,canonical,expires);
 SELECT * INTO STRICT r FROM vault_metadata.audit_mission_retirements WHERE instance_id=i AND operation_id=op FOR UPDATE;
 IF r.state='committed' THEN RAISE EXCEPTION 'retirement already committed; inspect only'; END IF;
 refs:=vault_metadata.audit_retirement_inventory(i,t,m);
 -- Same set difference as per-lot containment, as one anti-join: linear in
 -- the inventory, so a large Mission still fits the 30 second proof window.
 SELECT coalesce(jsonb_agg(v ORDER BY v->>'kind',v->>'id'),'[]'::jsonb) INTO expected
 FROM jsonb_array_elements(r.inventory) v WHERE NOT EXISTS(
  SELECT 1 FROM jsonb_array_elements(r.lots) lot CROSS JOIN LATERAL (
   SELECT 'audit_call' AS kind,c AS id FROM jsonb_array_elements_text(lot->'calls') c
   UNION ALL SELECT 'audit_event',e FROM jsonb_array_elements_text(lot->'events') e) gone
  WHERE gone.kind=v->>'kind' AND gone.id=v->>'id');
 IF refs IS DISTINCT FROM expected THEN RAISE EXCEPTION 'retirement inventory changed'; END IF;
 IF EXISTS(SELECT 1 FROM vault_metadata.audit_calls WHERE (instance_id,tenant_id,mission_id)=(i,t,m)
 AND expires_at>clock_timestamp()) THEN RAISE EXCEPTION 'audit retention not elapsed'; END IF;
 SELECT coalesce(array_agg(call_id ORDER BY call_id),ARRAY[]::uuid[]) INTO ids FROM (
 SELECT call_id FROM vault_metadata.audit_calls WHERE (instance_id,tenant_id,mission_id)=(i,t,m)
 ORDER BY call_id LIMIT batch FOR UPDATE) c;
 IF cardinality(ids)=0 THEN
  -- Closed scope that never had a correlated call: nothing to DELETE, so no
  -- lot and no audit179 receipt. Any other path to zero ids is refused.
  IF jsonb_array_length(r.lots)>0 OR EXISTS(SELECT 1 FROM jsonb_array_elements(r.inventory) v
   WHERE v->>'kind' IN ('audit_call','audit_event')) THEN
   RAISE EXCEPTION 'retirement ids mismatch'; END IF;
 ELSE
 WITH deleted AS (DELETE FROM vault_metadata.audit_events WHERE instance_id=i AND call_id=ANY(ids) RETURNING call_id::text||':'||seq::text AS event_id)
 SELECT coalesce(array_agg(event_id ORDER BY event_id),ARRAY[]::text[]) INTO events FROM deleted;
 WITH deleted AS (DELETE FROM vault_metadata.audit_calls WHERE instance_id=i AND call_id=ANY(ids) RETURNING call_id)
 SELECT coalesce(array_agg(call_id ORDER BY call_id),ARRAY[]::uuid[]) INTO removed FROM deleted;
 IF removed IS DISTINCT FROM ids THEN RAISE EXCEPTION 'retirement ids mismatch'; END IF;
 receipt:=gen_random_uuid();
 INSERT INTO vault_metadata.audit_calls(instance_id,call_id,actor_ref,tool)
 VALUES(i,receipt,'operator_'||substr(md5(session_user),1,16),'audit_expire');
 INSERT INTO vault_metadata.audit_events(instance_id,call_id,phase,step_id,outcome)
 VALUES(i,receipt,'public_terminal','00000000-0000-0000-0000-000000000000','completed');
 r.lots:=r.lots||jsonb_build_array(jsonb_build_object('calls',to_jsonb(removed),'events',to_jsonb(events),'receipt',receipt));
 END IF;
 SELECT EXISTS(SELECT 1 FROM vault_metadata.audit_calls WHERE (instance_id,tenant_id,mission_id)=(i,t,m)) INTO more;
 stamp:=clock_timestamp();
 IF expires<=stamp THEN RAISE EXCEPTION 'retention authority expired'; END IF;
 IF NOT more THEN
  envelope:=ident||jsonb_build_object('state','retired_confirmed','inventory_complete',true,'operation_id',op,
   'references',vault_metadata.audit_retirement_references(r.inventory),'contracts',jsonb_build_object('audit179','v1','holds846','v1'));
  envelope:=envelope||jsonb_build_object('receipt_sha256',encode(sha256(convert_to(envelope::text,'UTF8')),'hex'));
 END IF;
 UPDATE vault_metadata.audit_mission_retirements SET lots=r.lots,
 state=CASE WHEN more THEN 'prepared' ELSE 'committed' END,result=envelope,
 committed_at=CASE WHEN more THEN NULL ELSE stamp END,
 receipt_retain_until=CASE WHEN more THEN NULL ELSE stamp+interval '365 days' END
 WHERE instance_id=i AND operation_id=op;
 RETURN jsonb_build_object('has_more',more,'lot',r.lots->-1,'result',envelope);
END $$;

CREATE FUNCTION vault_metadata.audit_retirement_receipt(i text,t text,m text,op uuid)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('state',state,'result',result,'lots',lots,'retain_until',receipt_retain_until)
 FROM vault_metadata.audit_mission_retirements WHERE (instance_id,tenant_id,mission_id,operation_id)=(i,t,m,op);
$$;

-- Shared application wrap admission guard, before binding/wrap locks.
CREATE FUNCTION vault_metadata.audit_wrap_admit(i text,t text,m text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF t IS NULL OR t='' OR m IS NULL OR m='' THEN RAISE EXCEPTION 'wrap correlation incomplete'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(i,t,m)::text,846));
 INSERT INTO vault_metadata.audit_mission_holds(instance_id,tenant_id,mission_id) VALUES(i,t,m) ON CONFLICT DO NOTHING;
 IF EXISTS(SELECT 1 FROM vault_metadata.audit_mission_holds WHERE (instance_id,tenant_id,mission_id)=(i,t,m)
 AND claim_id IS NOT NULL) THEN RAISE EXCEPTION 'closed mission wrap correlation' USING ERRCODE='42501'; END IF;
END $$;
CREATE OR REPLACE FUNCTION vault_metadata.audit_expire_bound(wanted_instance text, wanted_tenant text, wanted_mission text,
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
  WHERE instance_id=wanted_instance AND mission_id IS NULL AND expires_at<=clock_timestamp()
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
  WHERE instance_id=wanted_instance AND mission_id IS NULL AND call_id=ANY(candidates) AND expires_at<=clock_timestamp()
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
  WHERE instance_id=wanted_instance AND mission_id IS NULL AND expires_at<=clock_timestamp()
  AND (wanted_mission IS NULL OR (tenant_id,mission_id)=(wanted_tenant,wanted_mission))
  AND vault_metadata.audit_retention_expired(instance_id,tenant_id,mission_id)
  AND NOT(call_id=ANY(ids))) INTO more;
 RETURN jsonb_build_object('calls',call_count,'events',event_count,'dry_run',dry_run,'has_more',more,'receipt',receipt);
END $$;
