// INPUT: 当前部署、真人管理员和用户变更。
// OUTPUT: 独立 Web 账号、平台成员权限与持久撤权事件。
// POS: 部署用户事务；不创建或变更组织成员关系。
package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (r *Repository) ListDeploymentMembers(ctx context.Context, deploymentID string) ([]DeploymentMemberRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT m.deployment_id, u.user_id, u.username, u.display_name, m.role, m.status,
       u.avatar, u.last_login_at, u.created_at, u.updated_at, m.updated_at, m.web_access_disabled
FROM deployment_memberships m
JOIN users u ON u.user_id = m.user_id
WHERE m.deployment_id = `+r.bind(1)+`
ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
         u.username ASC`, deploymentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	members := make([]DeploymentMemberRecord, 0)
	for rows.Next() {
		member, scanErr := scanDeploymentMember(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		members = append(members, member)
	}
	return members, rows.Err()
}

func (r *Repository) DeploymentMemberByID(ctx context.Context, deploymentID, userID string) (*DeploymentMemberRecord, error) {
	member, err := scanDeploymentMember(r.db.QueryRowContext(ctx, `
SELECT m.deployment_id, u.user_id, u.username, u.display_name, m.role, m.status,
       u.avatar, u.last_login_at, u.created_at, u.updated_at, m.updated_at, m.web_access_disabled
FROM deployment_memberships m
JOIN users u ON u.user_id = m.user_id
WHERE m.deployment_id = `+r.bind(1)+` AND m.user_id = `+r.bind(2), deploymentID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &member, err
}

func (r *Repository) CreateDeploymentMember(ctx context.Context, actorUserID string, record NewMemberRecord) (*DeploymentMemberRecord, error) {
	tx, err := r.beginIdentityWrite(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = r.requireDeploymentManager(ctx, tx, record.DeploymentID, actorUserID, record.Role); err != nil {
		return nil, err
	}
	if err = r.lockDeployment(ctx, tx, record.DeploymentID); err != nil {
		return nil, err
	}
	now := record.CreatedAt
	result, err := tx.ExecContext(ctx, `
INSERT INTO users (user_id, username, display_name, status, created_at, updated_at)
VALUES (`+r.dialect.BindList(6)+`) ON CONFLICT(username) DO NOTHING`,
		record.UserID, record.Username, record.DisplayName, "active", now, now,
	)
	if err != nil {
		return nil, err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return nil, ErrUsernameConflict
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO identities (identity_id, user_id, provider, subject, created_at, updated_at) VALUES (` + r.dialect.BindList(6) + `)`, []any{record.IdentityID, record.UserID, "password", record.Username, now, now}},
		{`INSERT INTO password_credentials (credential_id, user_id, password_hash, password_algo, password_updated_at, created_at, updated_at) VALUES (` + r.dialect.BindList(7) + `)`, []any{record.CredentialID, record.UserID, record.PasswordHash, "argon2id", now, now, now}},
		{`INSERT INTO deployment_memberships (deployment_id, user_id, role, status, created_at, updated_at, web_access_disabled) VALUES (` + r.dialect.BindList(7) + `)`, []any{record.DeploymentID, record.UserID, record.Role, "active", now, now, false}},
	}
	for _, statement := range statements {
		if _, err = tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &DeploymentMemberRecord{
		DeploymentID: record.DeploymentID, UserID: record.UserID,
		Username: record.Username, DisplayName: record.DisplayName,
		Role: record.Role, MembershipStatus: "active", CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (r *Repository) UpdateDeploymentMember(
	ctx context.Context,
	deploymentID string,
	userID string,
	actorUserID string,
	expectedRole string,
	expectedStatus string,
	expectedVersion int64,
	nextRole string,
	nextStatus string,
	nextName string,
	now time.Time,
) (*DeploymentMemberRecord, error) {
	tx, err := r.beginIdentityWrite(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = r.lockDeployment(ctx, tx, deploymentID); err != nil {
		return nil, err
	}
	target, err := r.queryDeploymentMember(ctx, tx, deploymentID, userID)
	if err != nil {
		return nil, err
	}
	if target.Role != expectedRole || target.MembershipStatus != expectedStatus || target.UpdatedAt.UnixMicro() != expectedVersion {
		return nil, ErrStateConflict
	}
	if err = r.requireDeploymentManager(ctx, tx, deploymentID, actorUserID, target.Role); err != nil {
		return nil, err
	}
	if err = r.requireDeploymentManager(ctx, tx, deploymentID, actorUserID, nextRole); err != nil {
		return nil, err
	}
	if actorUserID == userID && nextStatus == "revoked" {
		return nil, ErrStateConflict
	}
	if _, err = tx.ExecContext(ctx, `
UPDATE deployment_memberships SET role = `+r.bind(1)+`, status = `+r.bind(2)+`, updated_at = `+r.bind(3)+`
WHERE deployment_id = `+r.bind(4)+` AND user_id = `+r.bind(5),
		nextRole, nextStatus, now, deploymentID, userID,
	); err != nil {
		return nil, err
	}
	if nextName != target.DisplayName {
		result, updateErr := tx.ExecContext(ctx, `UPDATE users SET display_name = `+r.bind(1)+`, updated_at = `+r.bind(2)+` WHERE user_id = `+r.bind(3)+` AND display_name = `+r.bind(4), nextName, now, userID, target.DisplayName)
		if updateErr != nil {
			return nil, updateErr
		}
		if count, _ := result.RowsAffected(); count != 1 {
			return nil, ErrStateConflict
		}
		if err = r.appendProfileInvalidations(ctx, tx, userID, now); err != nil {
			return nil, err
		}
	}
	if nextStatus == "revoked" {
		if _, err = tx.ExecContext(ctx, `
UPDATE sessions SET revoked_at = `+r.bind(1)+`, updated_at = `+r.bind(2)+`
WHERE deployment_id = `+r.bind(3)+` AND user_id = `+r.bind(4)+` AND revoked_at IS NULL`,
			now, now, deploymentID, userID,
		); err != nil {
			return nil, err
		}
	}
	if target.Role != nextRole || target.MembershipStatus != nextStatus {
		if err = r.appendIdentityInvalidation(
			ctx,
			tx,
			deploymentID,
			userID,
			"",
			"principal_changed",
			now,
		); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	target.Role, target.MembershipStatus, target.DisplayName, target.UpdatedAt = nextRole, nextStatus, nextName, now
	return &target, nil
}

func (r *Repository) queryDeploymentMember(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	userID string,
) (DeploymentMemberRecord, error) {
	member, err := scanDeploymentMember(tx.QueryRowContext(ctx, `
SELECT m.deployment_id, u.user_id, u.username, u.display_name, m.role, m.status,
       u.avatar, u.last_login_at, u.created_at, u.updated_at, m.updated_at, m.web_access_disabled
FROM deployment_memberships m
JOIN users u ON u.user_id = m.user_id
WHERE m.deployment_id = `+r.bind(1)+` AND m.user_id = `+r.bind(2), deploymentID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return DeploymentMemberRecord{}, ErrNotFound
	}
	return member, err
}

// requireDeploymentManager 在身份写锁内校验平台权限，组织角色不能授予部署管理权。
func (r *Repository) requireDeploymentManager(ctx context.Context, tx *sql.Tx, deploymentID, userID, targetRole string) error {
	var role string
	err := tx.QueryRowContext(ctx, `SELECT m.role FROM deployment_memberships m
JOIN users u ON u.user_id=m.user_id JOIN deployments d ON d.deployment_id=m.deployment_id
WHERE m.deployment_id=`+r.bind(1)+` AND m.user_id=`+r.bind(2)+`
AND m.status='active' AND u.status='active' AND d.status='active'`, deploymentID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStateConflict
	}
	if err != nil {
		return err
	}
	if targetRole == "owner" || (role != "owner" && (role != "admin" || targetRole != "member")) {
		return ErrStateConflict
	}
	return nil
}
