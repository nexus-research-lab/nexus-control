-- +goose Up
ALTER TABLE identity_invalidations ADD COLUMN session_id TEXT;

-- +goose Down
ALTER TABLE identity_invalidations DROP COLUMN session_id;
