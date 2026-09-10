-- +goose Up
CREATE TABLE organization_invitations (
    invitation_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    created_by_user_id TEXT NOT NULL,
    accepted_by_user_id TEXT,
    expires_at DATETIME NOT NULL,
    accepted_at DATETIME,
    revoked_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    CHECK (accepted_at IS NULL OR revoked_at IS NULL),
    CHECK ((accepted_by_user_id IS NULL) = (accepted_at IS NULL)),
    FOREIGN KEY (organization_id) REFERENCES organizations (organization_id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users (user_id),
    FOREIGN KEY (accepted_by_user_id) REFERENCES users (user_id)
);
CREATE INDEX idx_control_organization_invitations
    ON organization_invitations (organization_id, created_at DESC);

-- +goose Down
DROP TABLE organization_invitations;
