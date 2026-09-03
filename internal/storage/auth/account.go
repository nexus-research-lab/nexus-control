package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

func (r *Repository) SetupRequired(ctx context.Context) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM deployment_memberships WHERE status = 'active'`).Scan(&count)
	return count == 0, err
}

func (r *Repository) CreateOwner(ctx context.Context, record OwnerRecord) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = r.lockControlState(ctx, tx); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM deployment_memberships WHERE status = 'active'`).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrAlreadySetup
	}
	now := record.CreatedAt
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO deployments (deployment_id, name, status, created_at, updated_at) VALUES (` + r.dialect.BindList(5) + `)`, []any{record.DeploymentID, record.DeploymentName, "active", now, now}},
		{`INSERT INTO users (user_id, username, display_name, status, created_at, updated_at) VALUES (` + r.dialect.BindList(6) + `)`, []any{record.UserID, record.Username, record.DisplayName, "active", now, now}},
		{`INSERT INTO identities (identity_id, user_id, provider, subject, created_at, updated_at) VALUES (` + r.dialect.BindList(6) + `)`, []any{record.IdentityID, record.UserID, "password", record.Username, now, now}},
		{`INSERT INTO password_credentials (credential_id, user_id, password_hash, password_algo, password_updated_at, created_at, updated_at) VALUES (` + r.dialect.BindList(7) + `)`, []any{record.CredentialID, record.UserID, record.PasswordHash, "argon2id", now, now, now}},
		{`INSERT INTO deployment_memberships (deployment_id, user_id, role, status, created_at, updated_at) VALUES (` + r.dialect.BindList(6) + `)`, []any{record.DeploymentID, record.UserID, "owner", "active", now, now}},
	}
	for _, statement := range statements {
		if _, err = tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *Repository) ActiveRole(ctx context.Context, userID string) (string, error) {
	var role string
	err := r.db.QueryRowContext(ctx, `
SELECT m.role FROM deployment_memberships m JOIN users u ON u.user_id = m.user_id
WHERE m.user_id = `+r.bind(1)+` AND m.status = 'active' AND u.status = 'active'
ORDER BY m.created_at ASC LIMIT 1`, strings.TrimSpace(userID)).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return role, err
}

func (r *Repository) UserByID(ctx context.Context, userID string) (*UserRecord, error) {
	var user UserRecord
	var avatar sql.NullString
	var lastLogin sql.NullTime
	err := r.db.QueryRowContext(ctx, `
SELECT user_id, username, display_name, status, avatar, last_login_at, created_at, updated_at
FROM users WHERE user_id = `+r.bind(1), strings.TrimSpace(userID)).Scan(
		&user.UserID, &user.Username, &user.DisplayName, &user.Status, &avatar,
		&lastLogin, &user.CreatedAt, &user.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	user.Avatar = avatar.String
	user.LastLoginAt = nullTimePointer(lastLogin)
	user.CreatedAt, user.UpdatedAt = user.CreatedAt.UTC(), user.UpdatedAt.UTC()
	return &user, nil
}

func (r *Repository) UpdateAvatar(ctx context.Context, userID, avatar string, now time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
UPDATE users SET avatar = `+r.bind(1)+`, updated_at = `+r.bind(2)+`
WHERE user_id = `+r.bind(3)+` AND status = 'active'`, nullableString(avatar), now, strings.TrimSpace(userID))
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrNotFound
	}
	rows, err := tx.QueryContext(ctx, `
SELECT deployment_id FROM deployment_memberships
WHERE user_id = `+r.bind(1)+` AND status = 'active'`, strings.TrimSpace(userID))
	if err != nil {
		return err
	}
	var deployments []string
	for rows.Next() {
		var deploymentID string
		if err = rows.Scan(&deploymentID); err != nil {
			_ = rows.Close()
			return err
		}
		deployments = append(deployments, deploymentID)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, deploymentID := range deployments {
		if err = r.appendIdentityInvalidation(
			ctx,
			tx,
			deploymentID,
			strings.TrimSpace(userID),
			"",
			"profile_changed",
			now,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *Repository) ImportDeployment(
	ctx context.Context,
	deploymentID string,
	deploymentName string,
	items []ImportedUserRecord,
	now time.Time,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = r.lockControlState(ctx, tx); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM deployment_memberships WHERE status = 'active'`).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrAlreadySetup
	}
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO deployments (deployment_id, name, status, created_at, updated_at) VALUES (`+r.dialect.BindList(5)+`)`,
		deploymentID, deploymentName, "active", now, now,
	); err != nil {
		return err
	}
	for _, item := range items {
		if err = r.importUser(ctx, tx, deploymentID, item); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *Repository) importUser(ctx context.Context, tx *sql.Tx, deploymentID string, item ImportedUserRecord) error {
	user := item.User
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users (user_id, username, display_name, status, avatar, last_login_at, created_at, updated_at) VALUES (` + r.dialect.BindList(8) + `)`, []any{user.UserID, user.Username, user.DisplayName, user.Status, nullableString(user.Avatar), nullableTime(user.LastLoginAt), user.CreatedAt, user.UpdatedAt}},
		{`INSERT INTO identities (identity_id, user_id, provider, subject, created_at, updated_at) VALUES (` + r.dialect.BindList(6) + `)`, []any{item.IdentityID, user.UserID, "password", user.Username, user.CreatedAt, user.UpdatedAt}},
		{`INSERT INTO password_credentials (credential_id, user_id, password_hash, password_algo, password_updated_at, created_at, updated_at) VALUES (` + r.dialect.BindList(7) + `)`, []any{item.CredentialID, user.UserID, item.PasswordHash, item.PasswordAlgorithm, item.PasswordUpdatedAt, item.CredentialCreated, item.CredentialUpdated}},
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	membershipStatus := "active"
	if user.Status != "active" {
		membershipStatus = "revoked"
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO deployment_memberships (deployment_id, user_id, role, status, created_at, updated_at) VALUES (`+r.dialect.BindList(6)+`)`,
		deploymentID, user.UserID, item.Role, membershipStatus, user.CreatedAt, user.UpdatedAt,
	)
	return err
}
