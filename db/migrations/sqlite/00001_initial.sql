-- +goose Up
CREATE TABLE control_state (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1)
);
INSERT INTO control_state (singleton_id) VALUES (1);

CREATE TABLE deployments (
    deployment_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    avatar TEXT,
    last_login_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
CREATE UNIQUE INDEX uq_control_users_username ON users (username);

CREATE TABLE identities (
    identity_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE (provider, subject),
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
);

CREATE TABLE password_credentials (
    credential_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_algo TEXT NOT NULL CHECK (password_algo = 'argon2id'),
    password_updated_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
);

CREATE TABLE deployment_memberships (
    deployment_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (deployment_id, user_id),
    FOREIGN KEY (deployment_id) REFERENCES deployments (deployment_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
);
CREATE INDEX idx_control_memberships_user ON deployment_memberships (user_id, status);

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    session_token_hash TEXT NOT NULL UNIQUE,
    auth_method TEXT NOT NULL CHECK (auth_method = 'password'),
    expires_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    client_ip TEXT,
    user_agent TEXT,
    revoked_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (deployment_id, user_id) REFERENCES deployment_memberships (deployment_id, user_id) ON DELETE CASCADE
);
CREATE INDEX idx_control_sessions_user ON sessions (user_id);
CREATE INDEX idx_control_sessions_expires ON sessions (expires_at);

CREATE TABLE password_change_receipts (
    user_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    effect TEXT NOT NULL CHECK (effect IN ('committed', 'not_applied')),
    resolved_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (user_id, request_id),
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
);

-- +goose Down
DROP TABLE password_change_receipts;
DROP TABLE sessions;
DROP TABLE deployment_memberships;
DROP TABLE password_credentials;
DROP TABLE identities;
DROP TABLE users;
DROP TABLE deployments;
DROP TABLE control_state;
