package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (r *Repository) ListMembers(ctx context.Context, deploymentID, organizationID string) ([]DeploymentMemberRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT m.deployment_id, u.user_id, u.username, u.display_name, om.role, om.status,
       u.avatar, u.last_login_at, u.created_at, u.updated_at, om.updated_at
FROM deployment_memberships m
JOIN users u ON u.user_id = m.user_id
JOIN organization_memberships om ON om.user_id = m.user_id
WHERE m.deployment_id = `+r.bind(1)+` AND om.organization_id = `+r.bind(2)+`
ORDER BY CASE om.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
         u.username ASC`, deploymentID, organizationID)
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

func (r *Repository) ListActiveMembers(ctx context.Context, deploymentID, organizationID string) ([]DeploymentMemberRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT m.deployment_id, u.user_id, u.username, u.display_name, m.role, m.status,
       u.avatar, u.last_login_at, u.created_at, u.updated_at, m.updated_at
FROM deployment_memberships m
JOIN users u ON u.user_id = m.user_id
JOIN organization_memberships om ON om.user_id = m.user_id
JOIN organizations o ON o.organization_id = om.organization_id AND o.deployment_id = m.deployment_id
WHERE m.deployment_id = `+r.bind(1)+` AND om.organization_id = `+r.bind(2)+`
  AND m.status = 'active' AND om.status = 'active' AND o.status = 'active' AND u.status = 'active'
ORDER BY u.display_name ASC, u.username ASC`, deploymentID, organizationID)
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

func (r *Repository) MemberByID(ctx context.Context, deploymentID, organizationID, userID string) (*DeploymentMemberRecord, error) {
	member, err := scanDeploymentMember(r.db.QueryRowContext(ctx, `
SELECT m.deployment_id, u.user_id, u.username, u.display_name, om.role, om.status,
       u.avatar, u.last_login_at, u.created_at, u.updated_at, om.updated_at
FROM deployment_memberships m
JOIN users u ON u.user_id = m.user_id
JOIN organization_memberships om ON om.user_id = m.user_id
WHERE m.deployment_id = `+r.bind(1)+` AND om.organization_id = `+r.bind(2)+`
  AND m.user_id = `+r.bind(3), deploymentID, organizationID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &member, err
}

func (r *Repository) CreateMember(ctx context.Context, record NewMemberRecord) (*DeploymentMemberRecord, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
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
		{`INSERT INTO deployment_memberships (deployment_id, user_id, role, status, created_at, updated_at) VALUES (` + r.dialect.BindList(6) + `)`, []any{record.DeploymentID, record.UserID, record.Role, "active", now, now}},
		{`INSERT INTO organization_memberships (organization_id, user_id, role, status, created_at, updated_at) VALUES (` + r.dialect.BindList(6) + `)`, []any{record.OrganizationID, record.UserID, record.Role, "active", now, now}},
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

func (r *Repository) UpdateMember(
	ctx context.Context,
	deploymentID string,
	organizationID string,
	userID string,
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
	target, err := r.queryOrganizationMember(ctx, tx, deploymentID, organizationID, userID)
	if err != nil {
		return nil, err
	}
	if target.Role != expectedRole || target.MembershipStatus != expectedStatus || target.UpdatedAt.UnixMicro() != expectedVersion {
		return nil, ErrStateConflict
	}
	if target.Role == "owner" && target.MembershipStatus == "active" &&
		(nextRole != "owner" || nextStatus != "active") {
		var owners int
		if err = tx.QueryRowContext(ctx, `
SELECT COUNT(*) FROM organization_memberships
WHERE organization_id = `+r.bind(1)+` AND role = 'owner' AND status = 'active'`, organizationID).Scan(&owners); err != nil {
			return nil, err
		}
		if owners <= 1 {
			return nil, ErrLastOwner
		}
	}
	if _, err = tx.ExecContext(ctx, `
UPDATE deployment_memberships SET role = `+r.bind(1)+`, status = `+r.bind(2)+`, updated_at = `+r.bind(3)+`
WHERE deployment_id = `+r.bind(4)+` AND user_id = `+r.bind(5),
		nextRole, nextStatus, now, deploymentID, userID,
	); err != nil {
		return nil, err
	}
	organizationResult, err := tx.ExecContext(ctx, `
UPDATE organization_memberships SET role = `+r.bind(1)+`, status = `+r.bind(2)+`, updated_at = `+r.bind(3)+`
WHERE user_id = `+r.bind(4)+` AND organization_id = `+r.bind(5),
		nextRole, nextStatus, now, userID, organizationID)
	if err != nil {
		return nil, err
	}
	if count, rowsErr := organizationResult.RowsAffected(); rowsErr != nil || count != 1 {
		return nil, errors.Join(rowsErr, ErrStateConflict)
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
		if _, err = tx.ExecContext(ctx, `INSERT INTO identity_invalidations
			(deployment_id, user_id, reason, created_at, organization_id, membership_revoked)
			VALUES (`+r.dialect.BindList(6)+`)`, deploymentID, userID, "principal_changed", now, organizationID, nextStatus != "active"); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	target.Role, target.MembershipStatus, target.DisplayName, target.UpdatedAt = nextRole, nextStatus, nextName, now
	return &target, nil
}

func (r *Repository) queryOrganizationMember(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	organizationID string,
	userID string,
) (DeploymentMemberRecord, error) {
	member, err := scanDeploymentMember(tx.QueryRowContext(ctx, `
SELECT m.deployment_id, u.user_id, u.username, u.display_name, om.role, om.status,
       u.avatar, u.last_login_at, u.created_at, u.updated_at, om.updated_at
FROM deployment_memberships m
JOIN users u ON u.user_id = m.user_id
JOIN organization_memberships om ON om.user_id = m.user_id
WHERE m.deployment_id = `+r.bind(1)+` AND om.organization_id = `+r.bind(2)+`
  AND m.user_id = `+r.bind(3), deploymentID, organizationID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return DeploymentMemberRecord{}, ErrNotFound
	}
	return member, err
}

func scanDeploymentMember(row rowScanner) (DeploymentMemberRecord, error) {
	var member DeploymentMemberRecord
	var avatar sql.NullString
	var lastLogin sql.NullTime
	var membershipUpdatedAt time.Time
	err := row.Scan(
		&member.DeploymentID, &member.UserID, &member.Username, &member.DisplayName,
		&member.Role, &member.MembershipStatus, &avatar, &lastLogin,
		&member.CreatedAt, &member.UpdatedAt, &membershipUpdatedAt,
	)
	if membershipUpdatedAt.After(member.UpdatedAt) {
		member.UpdatedAt = membershipUpdatedAt
	}
	member.Avatar = avatar.String
	member.LastLoginAt = nullTimePointer(lastLogin)
	member.CreatedAt, member.UpdatedAt = member.CreatedAt.UTC(), member.UpdatedAt.UTC()
	return member, err
}
