-- +goose Up
ALTER TABLE deployment_memberships ADD COLUMN web_access_disabled BOOLEAN NOT NULL DEFAULT FALSE;
-- 只回填注册与接受邀请为同一事务的账号，已有账号后来入组不降权。
UPDATE deployment_memberships SET web_access_disabled = TRUE
WHERE EXISTS (
    SELECT 1 FROM users u
    JOIN organization_invitations i ON i.accepted_by_user_id = u.user_id
    JOIN organizations o ON o.organization_id = i.organization_id
    WHERE u.user_id = deployment_memberships.user_id
      AND o.deployment_id = deployment_memberships.deployment_id
      AND i.accepted_at = u.created_at
);

-- +goose Down
ALTER TABLE deployment_memberships DROP COLUMN web_access_disabled;
