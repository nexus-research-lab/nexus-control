-- +goose Up
CREATE TABLE identity_invalidations (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at DATETIME NOT NULL
);

-- +goose Down
DROP TABLE identity_invalidations;
