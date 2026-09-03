package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (r *Repository) EffectiveEntitlement(
	ctx context.Context,
	deploymentID string,
	userID string,
) (*EntitlementRecord, error) {
	record, err := scanEntitlement(r.db.QueryRowContext(ctx, `
SELECT m.deployment_id, m.user_id, p.plan_key, p.display_name, p.monthly_token_limit,
       p.updated_at, e.updated_at
FROM deployment_memberships m
LEFT JOIN member_entitlements e
  ON e.deployment_id = m.deployment_id AND e.user_id = m.user_id
JOIN subscription_plans p
  ON p.deployment_id = m.deployment_id AND p.plan_key = COALESCE(e.plan_key, 'free')
WHERE m.deployment_id = `+r.bind(1)+` AND m.user_id = `+r.bind(2), deploymentID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &record, err
}

func (r *Repository) ListSubscriptionPlans(
	ctx context.Context,
	deploymentID string,
) ([]SubscriptionPlanRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT deployment_id, plan_key, display_name, status, monthly_token_limit,
       notes, sort_order, created_at, updated_at
FROM subscription_plans
WHERE deployment_id = `+r.bind(1)+`
ORDER BY sort_order ASC, plan_key ASC`, deploymentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]SubscriptionPlanRecord, 0)
	for rows.Next() {
		record, scanErr := scanSubscriptionPlan(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (r *Repository) ListSubscriptionAccounts(
	ctx context.Context,
	deploymentID string,
) ([]SubscriptionAccountRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT m.deployment_id, u.user_id, u.username, u.display_name, m.role, m.status,
       u.avatar, u.last_login_at, u.created_at, u.updated_at,
       p.plan_key, p.display_name, p.monthly_token_limit,
       p.updated_at, e.updated_at
FROM deployment_memberships m
JOIN users u ON u.user_id = m.user_id
LEFT JOIN member_entitlements e
  ON e.deployment_id = m.deployment_id AND e.user_id = m.user_id
JOIN subscription_plans p
  ON p.deployment_id = m.deployment_id AND p.plan_key = COALESCE(e.plan_key, 'free')
WHERE m.deployment_id = `+r.bind(1)+`
ORDER BY u.created_at ASC, u.user_id ASC`, deploymentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]SubscriptionAccountRecord, 0)
	for rows.Next() {
		var record SubscriptionAccountRecord
		var avatar sql.NullString
		var lastLogin sql.NullTime
		var monthlyLimit sql.NullInt64
		var planUpdatedAt time.Time
		var entitlementUpdatedAt sql.NullTime
		if err = rows.Scan(
			&record.DeploymentID,
			&record.UserID,
			&record.Username,
			&record.DisplayName,
			&record.Role,
			&record.MembershipStatus,
			&avatar,
			&lastLogin,
			&record.CreatedAt,
			&record.UpdatedAt,
			&record.PlanKey,
			&record.PlanName,
			&monthlyLimit,
			&planUpdatedAt,
			&entitlementUpdatedAt,
		); err != nil {
			return nil, err
		}
		record.Avatar = avatar.String
		record.LastLoginAt = nullTimePointer(lastLogin)
		if monthlyLimit.Valid {
			record.MonthlyTokenLimit = &monthlyLimit.Int64
		}
		record.EntitlementUpdatedAt = planUpdatedAt
		if entitlementUpdatedAt.Valid && entitlementUpdatedAt.Time.After(planUpdatedAt) {
			record.EntitlementUpdatedAt = entitlementUpdatedAt.Time
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (r *Repository) UpsertSubscriptionPlan(
	ctx context.Context,
	record SubscriptionPlanRecord,
	now time.Time,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = r.lockDeployment(ctx, tx, record.DeploymentID); err != nil {
		return err
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	if err = r.upsertSubscriptionPlan(ctx, tx, record); err != nil {
		return err
	}
	users, err := r.entitlementUsers(ctx, tx, record.DeploymentID, record.PlanKey)
	if err != nil {
		return err
	}
	// ponytail: 套餐变更低频，首版按成员写可靠事件；单套餐成员量压垮事务后改为 deployment 级事件。
	for _, userID := range users {
		if err = r.appendIdentityInvalidation(
			ctx, tx, record.DeploymentID, userID, "", "entitlement_changed", now,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *Repository) SetMemberEntitlement(
	ctx context.Context,
	deploymentID string,
	userID string,
	planKey string,
	now time.Time,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = r.lockDeployment(ctx, tx, deploymentID); err != nil {
		return err
	}
	var status string
	err = tx.QueryRowContext(ctx, `
SELECT status FROM subscription_plans
WHERE deployment_id = `+r.bind(1)+` AND plan_key = `+r.bind(2), deploymentID, planKey).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrPlanNotFound
	}
	if err != nil {
		return err
	}
	if status != "active" {
		return ErrPlanNotFound
	}
	var current string
	err = tx.QueryRowContext(ctx, `
SELECT COALESCE(e.plan_key, 'free')
FROM deployment_memberships m
LEFT JOIN member_entitlements e
  ON e.deployment_id = m.deployment_id AND e.user_id = m.user_id
WHERE m.deployment_id = `+r.bind(1)+` AND m.user_id = `+r.bind(2), deploymentID, userID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if current == planKey {
		return nil
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO member_entitlements (deployment_id, user_id, plan_key, created_at, updated_at)
VALUES (`+r.dialect.BindList(5)+`)
ON CONFLICT(deployment_id, user_id) DO UPDATE SET
    plan_key = excluded.plan_key,
    updated_at = excluded.updated_at`, deploymentID, userID, planKey, now, now)
	if err != nil {
		return err
	}
	if err = r.appendIdentityInvalidation(
		ctx, tx, deploymentID, userID, "", "entitlement_changed", now,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) entitlementUsers(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	planKey string,
) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT m.user_id
FROM deployment_memberships m
LEFT JOIN member_entitlements e
  ON e.deployment_id = m.deployment_id AND e.user_id = m.user_id
WHERE m.deployment_id = `+r.bind(1)+`
  AND m.status = 'active'
  AND COALESCE(e.plan_key, 'free') = `+r.bind(2)+`
ORDER BY m.user_id ASC`, deploymentID, planKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]string, 0)
	for rows.Next() {
		var userID string
		if err = rows.Scan(&userID); err != nil {
			return nil, err
		}
		users = append(users, userID)
	}
	return users, rows.Err()
}

func (r *Repository) insertDefaultSubscriptionPlans(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	now time.Time,
) error {
	limit := int64(200000)
	defaults := []SubscriptionPlanRecord{
		{DeploymentID: deploymentID, PlanKey: "free", DisplayName: "Free", Status: "active", MonthlyTokenLimit: &limit, Notes: "默认免费额度", SortOrder: 10, CreatedAt: now, UpdatedAt: now},
		{DeploymentID: deploymentID, PlanKey: "admin", DisplayName: "Admin", Status: "active", Notes: "无限额度管理套餐", SortOrder: 90, CreatedAt: now, UpdatedAt: now},
	}
	for _, record := range defaults {
		if err := r.upsertSubscriptionPlan(ctx, tx, record); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) upsertSubscriptionPlan(
	ctx context.Context,
	tx *sql.Tx,
	record SubscriptionPlanRecord,
) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO subscription_plans (
    deployment_id, plan_key, display_name, status, monthly_token_limit,
    notes, sort_order, created_at, updated_at
) VALUES (`+r.dialect.BindList(9)+`)
ON CONFLICT(deployment_id, plan_key) DO UPDATE SET
    display_name = excluded.display_name,
    status = excluded.status,
    monthly_token_limit = excluded.monthly_token_limit,
    notes = excluded.notes,
    sort_order = excluded.sort_order,
    updated_at = excluded.updated_at`,
		record.DeploymentID,
		record.PlanKey,
		record.DisplayName,
		record.Status,
		record.MonthlyTokenLimit,
		record.Notes,
		record.SortOrder,
		record.CreatedAt,
		record.UpdatedAt,
	)
	return err
}

func scanSubscriptionPlan(scanner rowScanner) (SubscriptionPlanRecord, error) {
	var record SubscriptionPlanRecord
	var monthlyLimit sql.NullInt64
	err := scanner.Scan(
		&record.DeploymentID,
		&record.PlanKey,
		&record.DisplayName,
		&record.Status,
		&monthlyLimit,
		&record.Notes,
		&record.SortOrder,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if monthlyLimit.Valid {
		record.MonthlyTokenLimit = &monthlyLimit.Int64
	}
	return record, err
}

func scanEntitlement(scanner rowScanner) (EntitlementRecord, error) {
	var record EntitlementRecord
	var monthlyLimit sql.NullInt64
	var planUpdatedAt time.Time
	var entitlementUpdatedAt sql.NullTime
	err := scanner.Scan(
		&record.DeploymentID,
		&record.UserID,
		&record.PlanKey,
		&record.PlanName,
		&monthlyLimit,
		&planUpdatedAt,
		&entitlementUpdatedAt,
	)
	if monthlyLimit.Valid {
		record.MonthlyTokenLimit = &monthlyLimit.Int64
	}
	record.UpdatedAt = planUpdatedAt
	if entitlementUpdatedAt.Valid && entitlementUpdatedAt.Time.After(planUpdatedAt) {
		record.UpdatedAt = entitlementUpdatedAt.Time
	}
	return record, err
}
