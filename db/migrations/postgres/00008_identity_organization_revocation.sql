-- +goose Up
ALTER TABLE identity_invalidations ADD COLUMN organization_id TEXT NOT NULL DEFAULT '';
ALTER TABLE identity_invalidations ADD COLUMN membership_revoked BOOLEAN NOT NULL DEFAULT FALSE;
-- 已撤权成员也进入事件流，避免启用 Relay 消费时遗漏历史事实。
INSERT INTO identity_invalidations (deployment_id, user_id, reason, created_at, organization_id, membership_revoked)
SELECT o.deployment_id, m.user_id, 'principal_changed', CURRENT_TIMESTAMP, m.organization_id, TRUE
FROM organization_memberships m JOIN organizations o ON o.organization_id = m.organization_id
WHERE m.status <> 'active';

-- +goose Down
ALTER TABLE identity_invalidations DROP COLUMN membership_revoked;
ALTER TABLE identity_invalidations DROP COLUMN organization_id;
