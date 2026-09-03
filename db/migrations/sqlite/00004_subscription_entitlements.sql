-- +goose Up
CREATE TABLE subscription_plans (
    deployment_id TEXT NOT NULL REFERENCES deployments (deployment_id) ON DELETE CASCADE,
    plan_key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'archived')),
    monthly_token_limit INTEGER CHECK (monthly_token_limit IS NULL OR monthly_token_limit >= 0),
    notes TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 100,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (deployment_id, plan_key)
);

CREATE TABLE member_entitlements (
    deployment_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    plan_key TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (deployment_id, user_id),
    FOREIGN KEY (deployment_id, user_id)
        REFERENCES deployment_memberships (deployment_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (deployment_id, plan_key)
        REFERENCES subscription_plans (deployment_id, plan_key) ON DELETE RESTRICT
);
CREATE INDEX idx_control_member_entitlements_plan
    ON member_entitlements (deployment_id, plan_key);

INSERT INTO subscription_plans (
    deployment_id, plan_key, display_name, status, monthly_token_limit,
    notes, sort_order, created_at, updated_at
)
SELECT deployment_id, 'free', 'Free', 'active', 200000,
       '默认免费额度', 10, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM deployments;

INSERT INTO subscription_plans (
    deployment_id, plan_key, display_name, status, monthly_token_limit,
    notes, sort_order, created_at, updated_at
)
SELECT deployment_id, 'admin', 'Admin', 'active', NULL,
       '无限额度管理套餐', 90, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM deployments;

-- +goose Down
DROP TABLE member_entitlements;
DROP TABLE subscription_plans;
