CREATE SCHEMA vault_metadata;
CREATE TABLE vault_metadata.schema_version (version integer PRIMARY KEY CHECK(version=1));
INSERT INTO vault_metadata.schema_version VALUES (1);
CREATE TABLE vault_metadata.policies (
 instance_id text NOT NULL, policy_id text NOT NULL, payload jsonb NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 PRIMARY KEY(instance_id,policy_id),
 CHECK(payload->>'policy_id'=policy_id)
);
CREATE TABLE vault_metadata.tokens (
 instance_id text NOT NULL, token_hash text NOT NULL CHECK(token_hash ~ '^[0-9a-f]{64}$'),
 policy_id text, payload jsonb NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 PRIMARY KEY(instance_id,token_hash),
 FOREIGN KEY(instance_id,policy_id) REFERENCES vault_metadata.policies(instance_id,policy_id),
 CHECK(payload->>'hash'=token_hash), CHECK(NOT payload ? 'raw_token')
);
CREATE TABLE vault_metadata.token_vaults (
 instance_id text NOT NULL, token_hash text NOT NULL, vault_id text NOT NULL,
 PRIMARY KEY(instance_id,token_hash,vault_id),
 FOREIGN KEY(instance_id,token_hash) REFERENCES vault_metadata.tokens ON DELETE CASCADE
);
CREATE TABLE vault_metadata.mission_bindings (
 instance_id text NOT NULL, tenant_id text NOT NULL, policy_id text,
 payload jsonb NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 PRIMARY KEY(instance_id,tenant_id),
 FOREIGN KEY(instance_id,policy_id) REFERENCES vault_metadata.policies(instance_id,policy_id),
 CHECK(payload->>'tenant_id'=tenant_id)
);
CREATE TABLE vault_metadata.binding_vaults (
 instance_id text NOT NULL, tenant_id text NOT NULL, vault_id text NOT NULL,
 PRIMARY KEY(instance_id,tenant_id,vault_id),
 FOREIGN KEY(instance_id,tenant_id) REFERENCES vault_metadata.mission_bindings ON DELETE CASCADE
);
CREATE TABLE vault_metadata.wrap_registry (
 instance_id text NOT NULL, operation_id text NOT NULL, mission_id text NOT NULL,
 accessor text, vault_id text NOT NULL, secret_path text NOT NULL,
 status text NOT NULL CHECK(status IN ('pending','active','consuming','consumed','revoked','failed','unusable','consume_outcome_unknown')),
 payload jsonb NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 PRIMARY KEY(instance_id,operation_id,mission_id),
 UNIQUE(instance_id,accessor), CHECK(NOT payload ? 'wrap_token'),
 CHECK(payload->>'operation_id'=operation_id AND payload->>'mission_id'=mission_id)
);
CREATE TABLE vault_metadata.operation_receipts (
 instance_id text NOT NULL, mutation_id uuid NOT NULL, kind text NOT NULL,
 actor_hash text, intent_hash text NOT NULL, target jsonb NOT NULL,
 phase text NOT NULL, database_result text NOT NULL CHECK(database_result='committed'),
 created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(instance_id,mutation_id)
);
CREATE TABLE vault_metadata.installation (
 instance_id text PRIMARY KEY, mutation_id uuid NOT NULL, actor_hash text NOT NULL,
 FOREIGN KEY(instance_id,mutation_id) REFERENCES vault_metadata.operation_receipts DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX tokens_policy ON vault_metadata.tokens(instance_id,policy_id);
CREATE INDEX bindings_policy ON vault_metadata.mission_bindings(instance_id,policy_id);
CREATE INDEX wraps_target ON vault_metadata.wrap_registry(instance_id,vault_id,status);
