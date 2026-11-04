-- Exécuté dans la transaction opérateur sous le rôle owner NOLOGIN.
ALTER TABLE vault_metadata.schema_version DROP CONSTRAINT schema_version_version_check;
ALTER TABLE vault_metadata.schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=2) NOT VALID;
UPDATE vault_metadata.schema_version SET version=2 WHERE version=1;
ALTER TABLE vault_metadata.schema_version VALIDATE CONSTRAINT schema_version_version_check;
CREATE TABLE vault_metadata.audit_retention_policy (
 instance_id text PRIMARY KEY,
 retention_days integer NOT NULL CHECK(retention_days BETWEEN 1 AND 36500)
);
CREATE TABLE vault_metadata.audit_revision (
 instance_id text PRIMARY KEY, revision bigint NOT NULL CHECK(revision>0)
);
CREATE TABLE vault_metadata.audit_calls (
 instance_id text NOT NULL, call_id uuid NOT NULL,
 actor_ref text NOT NULL CHECK(actor_ref ~ '^(anonymous|(tok|mission|operator)_[0-9a-f]{16})$'),
 tool text NOT NULL CHECK(tool ~ '^[a-z][a-z0-9_]{0,63}$'),
 vault_id text NOT NULL DEFAULT '', tenant_id text, mission_id text, operation_id text,
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(instance_id,call_id), CHECK(expires_at>created_at)
);
CREATE TABLE vault_metadata.audit_events (
 seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 instance_id text NOT NULL, call_id uuid NOT NULL,
 phase text NOT NULL CHECK(phase IN ('admission','sql_step_committed','bao_step_outcome','compensation_outcome','public_terminal')),
 step_id uuid NOT NULL, mutation_id uuid,
 outcome text NOT NULL CHECK(outcome IN ('admitted','denied','confirmed','failed','unknown','completed','incomplete')),
 duration_ms double precision NOT NULL DEFAULT 0 CHECK(duration_ms>=0 AND duration_ms<'Infinity'::float8),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 UNIQUE(instance_id,call_id,phase,step_id),
 FOREIGN KEY(instance_id,call_id) REFERENCES vault_metadata.audit_calls,
 CHECK(phase<>'sql_step_committed' OR mutation_id IS NOT NULL AND mutation_id=step_id),
 CHECK(phase NOT IN ('admission','public_terminal') OR step_id='00000000-0000-0000-0000-000000000000'::uuid),
 CHECK((phase='admission' AND outcome IN ('admitted','denied'))
  OR (phase IN ('sql_step_committed','bao_step_outcome','compensation_outcome') AND outcome IN ('confirmed','failed','unknown'))
  OR (phase='public_terminal' AND outcome IN ('denied','failed','unknown','completed')))
);
CREATE INDEX audit_calls_expiry ON vault_metadata.audit_calls(instance_id,expires_at,call_id);
CREATE INDEX audit_calls_scope ON vault_metadata.audit_calls(instance_id,vault_id,tenant_id);
CREATE INDEX audit_events_page ON vault_metadata.audit_events(instance_id,seq);

CREATE FUNCTION vault_metadata.audit_fill_call() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE days integer;
BEGIN
 SELECT retention_days INTO STRICT days FROM vault_metadata.audit_retention_policy WHERE instance_id=NEW.instance_id;
 NEW.created_at:=clock_timestamp();
 NEW.expires_at:=NEW.created_at+make_interval(days=>days);
 RETURN NEW;
END $$;
CREATE TRIGGER audit_call_dates BEFORE INSERT ON vault_metadata.audit_calls
FOR EACH ROW EXECUTE FUNCTION vault_metadata.audit_fill_call();

CREATE FUNCTION vault_metadata.audit_fill_event() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 SELECT expires_at INTO STRICT NEW.expires_at FROM vault_metadata.audit_calls
 WHERE instance_id=NEW.instance_id AND call_id=NEW.call_id FOR KEY SHARE;
 NEW.created_at:=clock_timestamp();
 RETURN NEW;
END $$;
CREATE TRIGGER audit_event_dates BEFORE INSERT ON vault_metadata.audit_events
FOR EACH ROW EXECUTE FUNCTION vault_metadata.audit_fill_event();

CREATE FUNCTION vault_metadata.audit_bump_revision() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE instance text;
BEGIN
 IF TG_OP='DELETE' THEN instance:=OLD.instance_id; ELSE instance:=NEW.instance_id; END IF;
 INSERT INTO vault_metadata.audit_revision VALUES(instance,1)
 ON CONFLICT(instance_id) DO UPDATE SET revision=vault_metadata.audit_revision.revision+1;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER audit_call_revision AFTER INSERT OR DELETE ON vault_metadata.audit_calls
FOR EACH ROW EXECUTE FUNCTION vault_metadata.audit_bump_revision();
CREATE TRIGGER audit_event_revision AFTER INSERT OR DELETE ON vault_metadata.audit_events
FOR EACH ROW EXECUTE FUNCTION vault_metadata.audit_bump_revision();

CREATE FUNCTION vault_metadata.audit_expire(wanted_instance text, batch integer, dry_run boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE ids uuid[]; call_count integer; event_count integer; more boolean; receipt uuid;
BEGIN
 IF batch IS NULL OR batch<1 OR batch>500 OR dry_run IS NULL THEN
  RAISE EXCEPTION 'invalid audit expiry request';
 END IF;
 SELECT array_agg(call_id) INTO ids FROM (
  SELECT call_id FROM vault_metadata.audit_calls
  WHERE instance_id=wanted_instance AND expires_at<=clock_timestamp()
  ORDER BY expires_at,call_id LIMIT batch FOR UPDATE SKIP LOCKED
 ) selected;
 ids:=COALESCE(ids,ARRAY[]::uuid[]);
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
  AND NOT(call_id=ANY(ids))) INTO more;
 RETURN jsonb_build_object('calls',call_count,'events',event_count,'dry_run',dry_run,
  'has_more',more,'receipt',receipt);
END $$;
REVOKE ALL ON FUNCTION vault_metadata.audit_fill_call(),vault_metadata.audit_fill_event(),
 vault_metadata.audit_bump_revision(),vault_metadata.audit_expire(text,integer,boolean) FROM PUBLIC;
