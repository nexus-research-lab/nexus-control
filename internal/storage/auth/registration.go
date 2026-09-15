package auth

import (
	"context"
	"database/sql"
	"errors"
)

// RegisterAccount 创建无组织的普通账号；不创建隐式组织或授予管理权限。
func (r *Repository) RegisterAccount(ctx context.Context, record NewMemberRecord) error {
	tx, err := r.beginIdentityWrite(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var deployment string
	err = tx.QueryRowContext(ctx, `SELECT deployment_id FROM deployments WHERE status='active' ORDER BY created_at LIMIT 1`).Scan(&deployment)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO users (user_id,username,display_name,status,created_at,updated_at) VALUES (`+r.dialect.BindList(6)+`) ON CONFLICT(username) DO NOTHING`, record.UserID, record.Username, record.DisplayName, "active", record.CreatedAt, record.CreatedAt)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrUsernameConflict
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO identities (identity_id,user_id,provider,subject,created_at,updated_at) VALUES (` + r.dialect.BindList(6) + `)`, []any{record.IdentityID, record.UserID, "password", record.Username, record.CreatedAt, record.CreatedAt}},
		{`INSERT INTO password_credentials (credential_id,user_id,password_hash,password_algo,password_updated_at,created_at,updated_at) VALUES (` + r.dialect.BindList(7) + `)`, []any{record.CredentialID, record.UserID, record.PasswordHash, "argon2id", record.CreatedAt, record.CreatedAt, record.CreatedAt}},
		{`INSERT INTO deployment_memberships (deployment_id,user_id,role,status,created_at,updated_at) VALUES (` + r.dialect.BindList(6) + `)`, []any{deployment, record.UserID, "member", "active", record.CreatedAt, record.CreatedAt}},
	} {
		if _, err = tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}
