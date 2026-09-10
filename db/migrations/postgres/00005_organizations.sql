-- +goose Up
CREATE TABLE organizations (
    organization_id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL REFERENCES deployments (deployment_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_control_organizations_deployment ON organizations (deployment_id, status);

CREATE TABLE organization_memberships (
    organization_id TEXT NOT NULL REFERENCES organizations (organization_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id, user_id)
);
CREATE UNIQUE INDEX uq_control_active_organization_membership
    ON organization_memberships (user_id) WHERE status = 'active';

INSERT INTO organizations (organization_id, deployment_id, name, status, created_at, updated_at)
SELECT deployment_id, deployment_id, name, status, created_at, updated_at FROM deployments;

INSERT INTO organization_memberships (organization_id, user_id, role, status, created_at, updated_at)
SELECT deployment_id, user_id, role, status, created_at, updated_at FROM deployment_memberships;

-- +goose Down
DROP TABLE organization_memberships;
DROP TABLE organizations;
