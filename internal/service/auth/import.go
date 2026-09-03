package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	store "github.com/nexus-research-lab/nexus-control/internal/storage/auth"

	_ "modernc.org/sqlite"
)

// ImportNexusSQLite 从停止写入的 Nexus SQLite 复制账号和密码哈希。
// Session 故意不导入，切换后所有浏览器必须重新登录。
func (s *Service) ImportNexusSQLite(ctx context.Context, sourcePath, deploymentName string) error {
	state, err := s.State(ctx)
	if err != nil {
		return err
	}
	if !state.SetupRequired {
		return ErrAlreadySetup
	}
	source, err := openNexusSQLite(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	rows, err := source.QueryContext(ctx, `
SELECT u.user_id, u.username, u.display_name, u.role, u.status, u.avatar,
       u.last_login_at, u.created_at, u.updated_at,
       c.credential_id, c.password_hash, c.password_algo,
       c.password_updated_at, c.created_at, c.updated_at
FROM users u JOIN auth_password_credentials c ON c.user_id = u.user_id
WHERE u.user_id <> '__system__' ORDER BY u.created_at ASC`)
	if err != nil {
		return err
	}
	items := make([]store.ImportedUserRecord, 0)
	for rows.Next() {
		item, scanErr := scanImportedUser(rows)
		if scanErr != nil {
			_ = rows.Close()
			return scanErr
		}
		if _, err = normalizeRole(item.Role); err != nil || item.PasswordAlgorithm != "argon2id" {
			_ = rows.Close()
			return fmt.Errorf("用户 %s 的角色或密码算法不受支持", item.User.UserID)
		}
		item.IdentityID = newID("idn")
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	if len(items) == 0 {
		return errors.New("源 Nexus 没有可导入的密码用户")
	}
	plans, entitlements, err := scanImportedSubscriptions(ctx, source)
	if err != nil {
		return err
	}
	deploymentName = strings.TrimSpace(deploymentName)
	if deploymentName == "" {
		deploymentName = "Nexus"
	}
	err = s.repository.ImportDeployment(
		ctx,
		newID("dep"),
		deploymentName,
		items,
		plans,
		entitlements,
		s.now(),
	)
	if errors.Is(err, store.ErrAlreadySetup) {
		return ErrAlreadySetup
	}
	return err
}

// ImportNexusSubscriptionsSQLite 为已迁移账号的 Control 补导套餐与成员额度。
func (s *Service) ImportNexusSubscriptionsSQLite(ctx context.Context, sourcePath string) error {
	state, err := s.State(ctx)
	if err != nil {
		return err
	}
	if state.SetupRequired {
		return errors.New("Control 尚未初始化，请先执行 import-nexus")
	}
	source, err := openNexusSQLite(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	plans, entitlements, err := scanImportedSubscriptions(ctx, source)
	if err != nil {
		return err
	}
	if len(plans) == 0 {
		return errors.New("源 Nexus 没有可导入的订阅套餐")
	}
	return s.repository.ImportSubscriptions(ctx, plans, entitlements, s.now())
}

func openNexusSQLite(sourcePath string) (*sql.DB, error) {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return nil, errors.New("源 Nexus SQLite 路径无效")
	}
	absolutePath, err := filepath.Abs(sourcePath)
	if err != nil {
		return nil, errors.New("源 Nexus SQLite 路径无效")
	}
	sourceURL := (&url.URL{Scheme: "file", Path: absolutePath}).String() + "?mode=ro"
	return sql.Open("sqlite", sourceURL)
}

func scanImportedSubscriptions(
	ctx context.Context,
	source *sql.DB,
) ([]store.SubscriptionPlanRecord, []store.ImportedEntitlementRecord, error) {
	hasPlans, err := sqliteTableExists(ctx, source, "subscription_plans")
	if err != nil || !hasPlans {
		return nil, nil, err
	}
	rows, err := source.QueryContext(ctx, `
SELECT plan_key, display_name, status, monthly_token_limit, notes, sort_order, created_at, updated_at
FROM subscription_plans ORDER BY sort_order ASC, plan_key ASC`)
	if err != nil {
		return nil, nil, err
	}
	plans := make([]store.SubscriptionPlanRecord, 0)
	for rows.Next() {
		var plan store.SubscriptionPlanRecord
		var monthlyLimit sql.NullInt64
		if err = rows.Scan(
			&plan.PlanKey,
			&plan.DisplayName,
			&plan.Status,
			&monthlyLimit,
			&plan.Notes,
			&plan.SortOrder,
			&plan.CreatedAt,
			&plan.UpdatedAt,
		); err != nil {
			_ = rows.Close()
			return nil, nil, err
		}
		if monthlyLimit.Valid {
			plan.MonthlyTokenLimit = &monthlyLimit.Int64
		}
		if err = validateImportedSubscriptionPlan(UpsertSubscriptionPlanInput{
			PlanKey:           plan.PlanKey,
			DisplayName:       plan.DisplayName,
			Status:            plan.Status,
			MonthlyTokenLimit: plan.MonthlyTokenLimit,
			Notes:             plan.Notes,
			SortOrder:         plan.SortOrder,
		}); err != nil {
			_ = rows.Close()
			return nil, nil, err
		}
		plans = append(plans, plan)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return nil, nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, nil, err
	}
	hasEntitlements, err := sqliteTableExists(ctx, source, "user_subscriptions")
	if err != nil || !hasEntitlements {
		return plans, nil, err
	}
	rows, err = source.QueryContext(ctx, `
SELECT s.owner_user_id, s.plan_key, s.created_at, s.updated_at
FROM user_subscriptions s
JOIN users u ON u.user_id = s.owner_user_id
WHERE u.user_id <> '__system__'
ORDER BY s.owner_user_id ASC`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	entitlements := make([]store.ImportedEntitlementRecord, 0)
	for rows.Next() {
		var entitlement store.ImportedEntitlementRecord
		if err = rows.Scan(
			&entitlement.UserID,
			&entitlement.PlanKey,
			&entitlement.CreatedAt,
			&entitlement.UpdatedAt,
		); err != nil {
			return nil, nil, err
		}
		entitlements = append(entitlements, entitlement)
	}
	return plans, entitlements, rows.Err()
}

func sqliteTableExists(ctx context.Context, source *sql.DB, name string) (bool, error) {
	var count int
	err := source.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`,
		name,
	).Scan(&count)
	return count == 1, err
}

func scanImportedUser(row interface{ Scan(...any) error }) (store.ImportedUserRecord, error) {
	var item store.ImportedUserRecord
	var avatar sql.NullString
	var lastLogin sql.NullTime
	err := row.Scan(
		&item.User.UserID, &item.User.Username, &item.User.DisplayName, &item.Role,
		&item.User.Status, &avatar, &lastLogin, &item.User.CreatedAt, &item.User.UpdatedAt,
		&item.CredentialID, &item.PasswordHash, &item.PasswordAlgorithm,
		&item.PasswordUpdatedAt, &item.CredentialCreated, &item.CredentialUpdated,
	)
	item.User.Avatar = avatar.String
	if lastLogin.Valid {
		value := lastLogin.Time.UTC()
		item.User.LastLoginAt = &value
	}
	item.User.CreatedAt = item.User.CreatedAt.UTC()
	item.User.UpdatedAt = item.User.UpdatedAt.UTC()
	item.PasswordUpdatedAt = item.PasswordUpdatedAt.UTC()
	item.CredentialCreated = item.CredentialCreated.UTC()
	item.CredentialUpdated = item.CredentialUpdated.UTC()
	return item, err
}
