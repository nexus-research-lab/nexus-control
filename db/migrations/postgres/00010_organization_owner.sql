-- +goose Up
-- 旧版本允许多个组织所有者；只调整组织身份，保留原有平台角色。
UPDATE organization_memberships SET role='admin'
WHERE status='active' AND role='owner' AND user_id NOT IN (
    SELECT user_id FROM (
        SELECT user_id, ROW_NUMBER() OVER (PARTITION BY organization_id ORDER BY created_at,user_id) AS owner_rank
        FROM organization_memberships WHERE status='active' AND role='owner'
    ) ranked WHERE owner_rank=1
);
CREATE UNIQUE INDEX uq_control_organization_owner
ON organization_memberships(organization_id) WHERE status='active' AND role='owner';

-- +goose Down
DROP INDEX uq_control_organization_owner;
