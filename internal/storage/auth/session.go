package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (r *Repository) LoginRecord(ctx context.Context, username string) (*LoginRecord, error) {
	row := r.db.QueryRowContext(ctx, `
SELECT u.user_id, u.username, u.display_name, u.avatar, u.status,
       c.password_hash, m.deployment_id, m.role, m.status
FROM users u
JOIN password_credentials c ON c.user_id = u.user_id
JOIN deployment_memberships m ON m.user_id = u.user_id
JOIN deployments d ON d.deployment_id = m.deployment_id
WHERE u.username = `+r.bind(1)+` AND d.status = 'active'
ORDER BY m.created_at ASC LIMIT 1`, username)
	var record LoginRecord
	var avatar sql.NullString
	err := row.Scan(
		&record.Principal.UserID, &record.Principal.Username, &record.Principal.DisplayName,
		&avatar, &record.UserStatus, &record.PasswordHash, &record.Principal.DeploymentID,
		&record.Principal.Role, &record.MembershipState,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	record.Principal.Avatar = avatar.String
	return &record, nil
}

func (r *Repository) CreateSession(ctx context.Context, record SessionRecord) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at <= `+r.bind(1)+` OR revoked_at IS NOT NULL`,
		record.CreatedAt,
	); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `
INSERT INTO sessions (
    session_id, deployment_id, user_id, session_token_hash, auth_method,
    expires_at, last_seen_at, client_ip, user_agent, created_at, updated_at
) VALUES (`+r.dialect.BindList(11)+`)`,
		record.SessionID, record.Principal.DeploymentID, record.Principal.UserID,
		record.TokenHash, record.Principal.AuthMethod, record.ExpiresAt, record.CreatedAt,
		nullableString(record.ClientIP), nullableString(record.UserAgent), record.CreatedAt, record.CreatedAt,
	); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `
UPDATE users SET last_login_at = `+r.bind(1)+`, updated_at = `+r.bind(2)+`
WHERE user_id = `+r.bind(3), record.CreatedAt, record.CreatedAt, record.Principal.UserID); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) RevokeSession(
	ctx context.Context,
	tokenHash string,
	now time.Time,
) (*RevokedSessionRecord, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var revoked RevokedSessionRecord
	err = tx.QueryRowContext(ctx, `
UPDATE sessions SET revoked_at = `+r.bind(1)+`, updated_at = `+r.bind(2)+`
WHERE session_token_hash = `+r.bind(3)+` AND revoked_at IS NULL
RETURNING deployment_id, user_id, session_id`, now, now, tokenHash).Scan(
		&revoked.DeploymentID,
		&revoked.UserID,
		&revoked.SessionID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err = r.appendIdentityInvalidation(
		ctx,
		tx,
		revoked.DeploymentID,
		revoked.UserID,
		revoked.SessionID,
		"session_revoked",
		now,
	); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &revoked, nil
}

func (r *Repository) ResolveSessionByTokenHash(ctx context.Context, tokenHash string, now time.Time) (*PrincipalRecord, error) {
	return r.resolveSession(ctx, "s.session_token_hash = "+r.bind(1), tokenHash, now)
}

func (r *Repository) ResolveSessionByID(ctx context.Context, sessionID string, now time.Time) (*PrincipalRecord, error) {
	return r.resolveSession(ctx, "s.session_id = "+r.bind(1), sessionID, now)
}

func (r *Repository) resolveSession(ctx context.Context, predicate string, argument any, now time.Time) (*PrincipalRecord, error) {
	query := `
SELECT s.session_id, s.deployment_id, s.user_id, s.auth_method,
       u.username, u.display_name, u.avatar, m.role
FROM sessions s
JOIN users u ON u.user_id = s.user_id
JOIN deployment_memberships m ON m.deployment_id = s.deployment_id AND m.user_id = s.user_id
JOIN deployments d ON d.deployment_id = s.deployment_id
WHERE ` + predicate + ` AND s.revoked_at IS NULL AND s.expires_at > ` + r.bind(2) + `
  AND d.status = 'active' AND u.status = 'active' AND m.status = 'active'
LIMIT 1`
	var principal PrincipalRecord
	var avatar sql.NullString
	err := r.db.QueryRowContext(ctx, query, argument, now).Scan(
		&principal.SessionID, &principal.DeploymentID, &principal.UserID, &principal.AuthMethod,
		&principal.Username, &principal.DisplayName, &avatar, &principal.Role,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	principal.Avatar = avatar.String
	return &principal, nil
}

func (r *Repository) TouchSession(ctx context.Context, sessionID string, now time.Time) error {
	_, err := r.db.ExecContext(ctx, `
UPDATE sessions SET last_seen_at = `+r.bind(1)+`, updated_at = `+r.bind(2)+`
WHERE session_id = `+r.bind(3), now, now, sessionID)
	return err
}
