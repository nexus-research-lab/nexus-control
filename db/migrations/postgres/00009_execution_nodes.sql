-- +goose Up
CREATE TABLE execution_nodes (
    node_id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL REFERENCES deployments(deployment_id),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    owner_user_id TEXT NOT NULL REFERENCES users(user_id),
    parent_session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    credential_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    agent_ids_json TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX execution_nodes_owner ON execution_nodes(organization_id, owner_user_id);

-- +goose Down
DROP TABLE execution_nodes;
