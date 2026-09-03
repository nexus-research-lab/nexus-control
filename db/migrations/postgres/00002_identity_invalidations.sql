-- +goose Up
CREATE TABLE identity_invalidations (
    event_id BIGSERIAL PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

-- +goose Down
DROP TABLE identity_invalidations;
