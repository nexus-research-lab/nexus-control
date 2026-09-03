package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (r *Repository) PasswordCredential(ctx context.Context, userID string) (string, string, error) {
	var passwordHash, status string
	err := r.db.QueryRowContext(ctx, `
SELECT c.password_hash, u.status
FROM password_credentials c JOIN users u ON u.user_id = c.user_id
WHERE c.user_id = `+r.bind(1), userID).Scan(&passwordHash, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return passwordHash, status, err
}

func (r *Repository) PasswordChangeOutcome(ctx context.Context, userID, requestID string) (string, error) {
	var outcome string
	err := r.db.QueryRowContext(ctx, `
SELECT effect FROM password_change_receipts
WHERE user_id = `+r.bind(1)+` AND request_id = `+r.bind(2), userID, requestID).Scan(&outcome)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return outcome, err
}

func (r *Repository) TryCommitPasswordChange(
	ctx context.Context,
	userID string,
	requestID string,
	currentHash string,
	nextHash string,
	now time.Time,
) (PasswordAttempt, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return PasswordAttemptCredentialChanged, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
INSERT INTO password_change_receipts (user_id, request_id, effect, resolved_at, created_at)
VALUES (`+r.dialect.BindList(5)+`) ON CONFLICT(user_id, request_id) DO NOTHING`,
		userID, requestID, "committed", now, now,
	)
	if err != nil {
		return PasswordAttemptCredentialChanged, err
	}
	if claimed, _ := result.RowsAffected(); claimed == 0 {
		return PasswordAttemptExisting, nil
	}
	result, err = tx.ExecContext(ctx, `
UPDATE password_credentials
SET password_hash = `+r.bind(1)+`, password_updated_at = `+r.bind(2)+`, updated_at = `+r.bind(3)+`
WHERE user_id = `+r.bind(4)+` AND password_hash = `+r.bind(5), nextHash, now, now, userID, currentHash)
	if err != nil {
		return PasswordAttemptCredentialChanged, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return PasswordAttemptCredentialChanged, nil
	}
	if err = tx.Commit(); err != nil {
		return PasswordAttemptCredentialChanged, err
	}
	return PasswordAttemptCommitted, nil
}

func (r *Repository) SettlePasswordChange(ctx context.Context, userID, requestID, outcome string, now time.Time) error {
	_, err := r.db.ExecContext(ctx, `
INSERT INTO password_change_receipts (user_id, request_id, effect, resolved_at, created_at)
VALUES (`+r.dialect.BindList(5)+`) ON CONFLICT(user_id, request_id) DO NOTHING`,
		userID, requestID, outcome, now, now,
	)
	return err
}
