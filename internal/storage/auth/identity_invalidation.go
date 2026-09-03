package auth

import (
	"context"
	"database/sql"
	"time"
)

func (r *Repository) appendIdentityInvalidation(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	userID string,
	sessionID string,
	reason string,
	createdAt time.Time,
) error {
	// ponytail: 成员变更低频，首版保留完整序列；增长影响查询后再按 Nexus 副本最小游标归档。
	_, err := tx.ExecContext(ctx, `
INSERT INTO identity_invalidations (deployment_id, user_id, session_id, reason, created_at)
VALUES (`+r.dialect.BindList(5)+`)`, deploymentID, userID, nullableString(sessionID), reason, createdAt)
	return err
}

func (r *Repository) LatestIdentityInvalidationID(ctx context.Context) (int64, error) {
	var cursor int64
	err := r.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(event_id), 0) FROM identity_invalidations`).Scan(&cursor)
	return cursor, err
}

func (r *Repository) ListIdentityInvalidations(
	ctx context.Context,
	after int64,
	limit int,
) ([]IdentityInvalidationRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT event_id, deployment_id, user_id, session_id, reason, created_at
FROM identity_invalidations
WHERE event_id > `+r.bind(1)+`
ORDER BY event_id ASC
LIMIT `+r.bind(2), after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]IdentityInvalidationRecord, 0)
	for rows.Next() {
		var event IdentityInvalidationRecord
		var sessionID sql.NullString
		if err = rows.Scan(
			&event.EventID,
			&event.DeploymentID,
			&event.UserID,
			&sessionID,
			&event.Reason,
			&event.CreatedAt,
		); err != nil {
			return nil, err
		}
		event.SessionID = sessionID.String
		event.CreatedAt = event.CreatedAt.UTC()
		events = append(events, event)
	}
	return events, rows.Err()
}
