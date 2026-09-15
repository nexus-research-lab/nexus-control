-- +goose Up
CREATE TABLE agents (
    agent_id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL REFERENCES deployments (deployment_id) ON DELETE CASCADE,
    organization_id TEXT NOT NULL REFERENCES organizations (organization_id) ON DELETE CASCADE,
    owner_user_id TEXT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    source_agent_id TEXT NOT NULL,
    name TEXT NOT NULL,
    avatar TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (deployment_id, organization_id, owner_user_id, source_agent_id)
);
CREATE INDEX idx_control_agents_organization
    ON agents (deployment_id, organization_id, status, owner_user_id, name);

-- +goose Down
DROP TABLE agents;
