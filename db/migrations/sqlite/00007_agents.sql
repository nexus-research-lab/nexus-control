-- +goose Up
CREATE TABLE agents (
    agent_id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    source_agent_id TEXT NOT NULL,
    name TEXT NOT NULL,
    avatar TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE (deployment_id, organization_id, owner_user_id, source_agent_id),
    FOREIGN KEY (deployment_id) REFERENCES deployments (deployment_id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id) REFERENCES organizations (organization_id) ON DELETE CASCADE,
    FOREIGN KEY (owner_user_id) REFERENCES users (user_id) ON DELETE CASCADE
);
CREATE INDEX idx_control_agents_organization
    ON agents (deployment_id, organization_id, status, owner_user_id, name);

-- +goose Down
DROP TABLE agents;
