-- +goose Up
CREATE TABLE organization_invitations (
    invitation_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations (organization_id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    created_by_user_id TEXT NOT NULL REFERENCES users (user_id),
    accepted_by_user_id TEXT REFERENCES users (user_id),
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (accepted_at IS NULL OR revoked_at IS NULL),
    CHECK ((accepted_by_user_id IS NULL) = (accepted_at IS NULL))
);
CREATE INDEX idx_control_organization_invitations
    ON organization_invitations (organization_id, created_at DESC);

-- +goose Down
DROP TABLE organization_invitations;
