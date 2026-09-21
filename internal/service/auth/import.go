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

// controlSQLiteImportSchemaVersion 随 Control 权威 schema 更新，防止旧迁移器静默丢字段。
const controlSQLiteImportSchemaVersion = 11

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

// ImportControlSQLite 从旧 Control SQLite 向空目标库复制账号权威。
// Session 与密码修改回执不导入；身份失效序列保留原 ID，供 Relay 持久游标继续消费。
func (s *Service) ImportControlSQLite(ctx context.Context, sourcePath string) error {
	source, err := openReadOnlySQLite(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	tx, err := source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("打开 Control SQLite 只读事务: %w", err)
	}
	defer tx.Rollback()
	deployment, items, agents, plans, entitlements, err := scanControlSnapshot(ctx, tx)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT event_id, deployment_id, user_id, COALESCE(session_id, ''), reason, created_at, organization_id, membership_revoked FROM identity_invalidations ORDER BY event_id`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var event store.IdentityInvalidationRecord
		if err = rows.Scan(&event.EventID, &event.DeploymentID, &event.UserID, &event.SessionID, &event.Reason, &event.CreatedAt, &event.OrganizationID, &event.MembershipRevoked); err != nil {
			rows.Close()
			return err
		}
		deployment.Invalidations = append(deployment.Invalidations, event)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("完成 Control SQLite 只读快照: %w", err)
	}
	if err = s.repository.ImportControlDeployment(ctx, deployment, items, agents, plans, entitlements); errors.Is(err, store.ErrAlreadySetup) {
		return ErrAlreadySetup
	}
	return err
}

func scanControlSnapshot(
	ctx context.Context,
	source *sql.Tx,
) (
	store.ImportedDeploymentRecord,
	[]store.ImportedUserRecord,
	[]store.AgentRecord,
	[]store.SubscriptionPlanRecord,
	[]store.ImportedEntitlementRecord,
	error,
) {
	var schemaVersion int64
	if err := source.QueryRowContext(ctx, `
SELECT COALESCE(MAX(version_id), 0)
FROM goose_db_version
WHERE is_applied = 1`).Scan(&schemaVersion); err != nil {
		return store.ImportedDeploymentRecord{}, nil, nil, nil, nil, fmt.Errorf("读取源 Control schema 版本: %w", err)
	}
	if schemaVersion != controlSQLiteImportSchemaVersion {
		return store.ImportedDeploymentRecord{}, nil, nil, nil, nil, fmt.Errorf(
			"源 Control schema 版本必须为 %d，实际为 %d",
			controlSQLiteImportSchemaVersion,
			schemaVersion,
		)
	}
	var deploymentCount int
	if err := source.QueryRowContext(ctx, `SELECT COUNT(*) FROM deployments`).Scan(&deploymentCount); err != nil {
		return store.ImportedDeploymentRecord{}, nil, nil, nil, nil, fmt.Errorf("读取源 Control Deployment: %w", err)
	}
	if deploymentCount != 1 {
		return store.ImportedDeploymentRecord{}, nil, nil, nil, nil, fmt.Errorf("源 Control 必须且只能包含一个 Deployment，实际为 %d", deploymentCount)
	}
	var deployment store.ImportedDeploymentRecord
	if err := source.QueryRowContext(ctx, `
SELECT deployment_id, name, status, created_at, updated_at
FROM deployments`).Scan(
		&deployment.DeploymentID,
		&deployment.Name,
		&deployment.Status,
		&deployment.CreatedAt,
		&deployment.UpdatedAt,
	); err != nil {
		return store.ImportedDeploymentRecord{}, nil, nil, nil, nil, fmt.Errorf("读取源 Control Deployment: %w", err)
	}
	deployment.CreatedAt = deployment.CreatedAt.UTC()
	deployment.UpdatedAt = deployment.UpdatedAt.UTC()
	if strings.TrimSpace(deployment.DeploymentID) == "" || strings.TrimSpace(deployment.Name) == "" || (deployment.Status != "active" && deployment.Status != "disabled") {
		return store.ImportedDeploymentRecord{}, nil, nil, nil, nil, errors.New("源 Control Deployment 无效")
	}
	if err := scanControlOrganizations(ctx, source, &deployment); err != nil {
		return store.ImportedDeploymentRecord{}, nil, nil, nil, nil, err
	}
	items, err := scanControlUsers(ctx, source, deployment.DeploymentID)
	if err != nil {
		return store.ImportedDeploymentRecord{}, nil, nil, nil, nil, err
	}
	agents, err := scanControlAgents(ctx, source, deployment.DeploymentID)
	if err != nil {
		return store.ImportedDeploymentRecord{}, nil, nil, nil, nil, err
	}
	plans, err := scanControlPlans(ctx, source, deployment.DeploymentID)
	if err != nil {
		return store.ImportedDeploymentRecord{}, nil, nil, nil, nil, err
	}
	entitlements, err := scanControlEntitlements(ctx, source, deployment.DeploymentID)
	if err != nil {
		return store.ImportedDeploymentRecord{}, nil, nil, nil, nil, err
	}
	return deployment, items, agents, plans, entitlements, nil
}

func scanControlAgents(ctx context.Context, source *sql.Tx, deploymentID string) ([]store.AgentRecord, error) {
	rows, err := source.QueryContext(ctx, `
SELECT agent_id, deployment_id, organization_id, owner_user_id, source_agent_id,
       name, avatar, status, created_at, updated_at
FROM agents
WHERE deployment_id = ?
ORDER BY agent_id`, deploymentID)
	if err != nil {
		return nil, fmt.Errorf("读取源 Control Agent: %w", err)
	}
	defer rows.Close()
	agents := make([]store.AgentRecord, 0)
	for rows.Next() {
		agent, scanErr := store.ScanAgent(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("读取源 Control Agent: %w", scanErr)
		}
		agents = append(agents, agent)
	}
	return agents, rows.Err()
}

func scanControlUsers(
	ctx context.Context,
	source *sql.Tx,
	deploymentID string,
) ([]store.ImportedUserRecord, error) {
	var users, identities, credentials, memberships int
	if err := source.QueryRowContext(ctx, `
SELECT
    (SELECT COUNT(*) FROM users),
    (SELECT COUNT(*) FROM identities),
    (SELECT COUNT(*) FROM password_credentials),
    (SELECT COUNT(*) FROM deployment_memberships WHERE deployment_id = ?)`, deploymentID).Scan(
		&users,
		&identities,
		&credentials,
		&memberships,
	); err != nil {
		return nil, fmt.Errorf("检查源 Control 账号: %w", err)
	}
	if users == 0 || identities != users || credentials != users || memberships != users {
		return nil, fmt.Errorf(
			"源 Control 仅支持每个用户一组密码身份及当前 Deployment Membership：users=%d identities=%d credentials=%d memberships=%d",
			users,
			identities,
			credentials,
			memberships,
		)
	}
	rows, err := source.QueryContext(ctx, `
SELECT u.user_id, u.username, u.display_name, u.status, u.avatar,
       u.last_login_at, u.created_at, u.updated_at,
       i.identity_id, i.provider, i.subject, i.created_at, i.updated_at,
       c.credential_id, c.password_hash, c.password_algo,
       c.password_updated_at, c.created_at, c.updated_at,
       m.role, m.status, m.created_at, m.updated_at, m.web_access_disabled
FROM users u
JOIN identities i ON i.user_id = u.user_id
JOIN password_credentials c ON c.user_id = u.user_id
JOIN deployment_memberships m ON m.user_id = u.user_id
WHERE m.deployment_id = ?
ORDER BY u.created_at ASC, u.user_id ASC`, deploymentID)
	if err != nil {
		return nil, fmt.Errorf("读取源 Control 账号: %w", err)
	}
	defer rows.Close()
	items := make([]store.ImportedUserRecord, 0, users)
	for rows.Next() {
		var item store.ImportedUserRecord
		var avatar sql.NullString
		var lastLogin sql.NullTime
		var provider, subject string
		if err = rows.Scan(
			&item.User.UserID,
			&item.User.Username,
			&item.User.DisplayName,
			&item.User.Status,
			&avatar,
			&lastLogin,
			&item.User.CreatedAt,
			&item.User.UpdatedAt,
			&item.IdentityID,
			&provider,
			&subject,
			&item.IdentityCreated,
			&item.IdentityUpdated,
			&item.CredentialID,
			&item.PasswordHash,
			&item.PasswordAlgorithm,
			&item.PasswordUpdatedAt,
			&item.CredentialCreated,
			&item.CredentialUpdated,
			&item.Role,
			&item.MembershipStatus,
			&item.MembershipCreated,
			&item.MembershipUpdated,
			&item.WebAccessDisabled,
		); err != nil {
			return nil, err
		}
		item.User.Avatar = avatar.String
		if lastLogin.Valid {
			value := lastLogin.Time.UTC()
			item.User.LastLoginAt = &value
		}
		normalizeImportedControlTimes(&item)
		if err = validateImportedControlUser(item, provider, subject); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(items) != users {
		return nil, errors.New("源 Control Deployment 与 Organization Membership 不一致")
	}
	for _, item := range items {
		if item.Role == RoleOwner && item.MembershipStatus == MembershipActive {
			return items, nil
		}
	}
	return nil, errors.New("源 Control 没有 active owner")
}

func scanControlPlans(
	ctx context.Context,
	source *sql.Tx,
	deploymentID string,
) ([]store.SubscriptionPlanRecord, error) {
	rows, err := source.QueryContext(ctx, `
SELECT deployment_id, plan_key, display_name, status, monthly_token_limit,
       notes, sort_order, created_at, updated_at
FROM subscription_plans
WHERE deployment_id = ?
ORDER BY sort_order ASC, plan_key ASC`, deploymentID)
	if err != nil {
		return nil, fmt.Errorf("读取源 Control 套餐: %w", err)
	}
	defer rows.Close()
	plans := make([]store.SubscriptionPlanRecord, 0)
	for rows.Next() {
		var plan store.SubscriptionPlanRecord
		var monthlyLimit sql.NullInt64
		if err = rows.Scan(
			&plan.DeploymentID,
			&plan.PlanKey,
			&plan.DisplayName,
			&plan.Status,
			&monthlyLimit,
			&plan.Notes,
			&plan.SortOrder,
			&plan.CreatedAt,
			&plan.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if monthlyLimit.Valid {
			plan.MonthlyTokenLimit = &monthlyLimit.Int64
		}
		plan.CreatedAt = plan.CreatedAt.UTC()
		plan.UpdatedAt = plan.UpdatedAt.UTC()
		if err = validateImportedSubscriptionPlan(UpsertSubscriptionPlanInput{
			PlanKey:           plan.PlanKey,
			DisplayName:       plan.DisplayName,
			Status:            plan.Status,
			MonthlyTokenLimit: plan.MonthlyTokenLimit,
			Notes:             plan.Notes,
			SortOrder:         plan.SortOrder,
		}); err != nil {
			return nil, fmt.Errorf("源 Control 套餐 %s 无效: %w", plan.PlanKey, err)
		}
		plans = append(plans, plan)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(plans) == 0 {
		return nil, errors.New("源 Control 没有订阅套餐")
	}
	return plans, nil
}

func scanControlEntitlements(
	ctx context.Context,
	source *sql.Tx,
	deploymentID string,
) ([]store.ImportedEntitlementRecord, error) {
	rows, err := source.QueryContext(ctx, `
SELECT user_id, plan_key, created_at, updated_at
FROM member_entitlements
WHERE deployment_id = ?
ORDER BY user_id ASC`, deploymentID)
	if err != nil {
		return nil, fmt.Errorf("读取源 Control 成员额度: %w", err)
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
			return nil, err
		}
		entitlement.CreatedAt = entitlement.CreatedAt.UTC()
		entitlement.UpdatedAt = entitlement.UpdatedAt.UTC()
		entitlements = append(entitlements, entitlement)
	}
	return entitlements, rows.Err()
}

func validateImportedControlUser(item store.ImportedUserRecord, provider, subject string) error {
	if strings.TrimSpace(item.User.UserID) == "" || strings.TrimSpace(item.User.DisplayName) == "" ||
		strings.TrimSpace(item.IdentityID) == "" || strings.TrimSpace(item.CredentialID) == "" ||
		strings.TrimSpace(item.PasswordHash) == "" {
		return errors.New("源 Control 用户或密码身份字段不完整")
	}
	username, err := normalizeUsername(item.User.Username)
	if err != nil || username != item.User.Username {
		return fmt.Errorf("源 Control 用户 %s 的用户名无效", item.User.UserID)
	}
	if item.User.Status != StatusActive && item.User.Status != StatusDisabled {
		return fmt.Errorf("源 Control 用户 %s 的状态无效", item.User.UserID)
	}
	if _, err = normalizeRole(item.Role); err != nil {
		return fmt.Errorf("源 Control 用户 %s 的角色无效", item.User.UserID)
	}
	if item.MembershipStatus != MembershipActive && item.MembershipStatus != MembershipRevoked {
		return fmt.Errorf("源 Control 用户 %s 的 Membership 状态无效", item.User.UserID)
	}
	if provider != AuthPassword || subject != item.User.Username || item.PasswordAlgorithm != "argon2id" {
		return fmt.Errorf("源 Control 用户 %s 不是受支持的密码身份", item.User.UserID)
	}
	return nil
}

func normalizeImportedControlTimes(item *store.ImportedUserRecord) {
	item.User.CreatedAt = item.User.CreatedAt.UTC()
	item.User.UpdatedAt = item.User.UpdatedAt.UTC()
	item.PasswordUpdatedAt = item.PasswordUpdatedAt.UTC()
	item.CredentialCreated = item.CredentialCreated.UTC()
	item.CredentialUpdated = item.CredentialUpdated.UTC()
	item.MembershipCreated = item.MembershipCreated.UTC()
	item.MembershipUpdated = item.MembershipUpdated.UTC()
	item.IdentityCreated = item.IdentityCreated.UTC()
	item.IdentityUpdated = item.IdentityUpdated.UTC()
}

func openNexusSQLite(sourcePath string) (*sql.DB, error) {
	return openReadOnlySQLite(sourcePath)
}

func openReadOnlySQLite(sourcePath string) (*sql.DB, error) {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return nil, errors.New("源 SQLite 路径无效")
	}
	absolutePath, err := filepath.Abs(sourcePath)
	if err != nil {
		return nil, errors.New("源 SQLite 路径无效")
	}
	sourceURL := (&url.URL{Scheme: "file", Path: absolutePath}).String() + "?mode=ro"
	source, err := sql.Open("sqlite", sourceURL)
	if err != nil {
		return nil, err
	}
	source.SetMaxOpenConns(1)
	source.SetMaxIdleConns(1)
	if err = source.Ping(); err != nil {
		_ = source.Close()
		return nil, fmt.Errorf("打开源 SQLite: %w", err)
	}
	return source, nil
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
