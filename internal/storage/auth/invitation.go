package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (r *Repository) CreateOrganizationInvitation(
	ctx context.Context,
	record OrganizationInvitationRecord,
) (*OrganizationInvitationRecord, error) {
	_, err := r.db.ExecContext(ctx, `
INSERT INTO organization_invitations
    (invitation_id, organization_id, token_hash, role, created_by_user_id,
     expires_at, created_at, updated_at)
VALUES (`+r.dialect.BindList(8)+`)`,
		record.InvitationID, record.OrganizationID, record.TokenHash, record.Role,
		record.CreatedByUserID, record.ExpiresAt, record.CreatedAt, record.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func (r *Repository) ListOrganizationInvitations(
	ctx context.Context,
	organizationID string,
) ([]OrganizationInvitationRecord, error) {
	rows, err := r.db.QueryContext(ctx, invitationSelect+`
WHERE i.organization_id = `+r.bind(1)+`
ORDER BY i.created_at DESC LIMIT 100`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]OrganizationInvitationRecord, 0)
	for rows.Next() {
		record, scanErr := scanOrganizationInvitation(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (r *Repository) OrganizationInvitationByToken(
	ctx context.Context,
	tokenHash string,
) (*OrganizationInvitationRecord, error) {
	record, err := scanOrganizationInvitation(r.db.QueryRowContext(ctx, invitationSelect+`
WHERE i.token_hash = `+r.bind(1), tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvitationInvalid
	}
	return &record, err
}

func (r *Repository) OrganizationInvitationByID(
	ctx context.Context,
	organizationID string,
	invitationID string,
) (*OrganizationInvitationRecord, error) {
	record, err := scanOrganizationInvitation(r.db.QueryRowContext(ctx, invitationSelect+`
WHERE i.organization_id = `+r.bind(1)+` AND i.invitation_id = `+r.bind(2),
		organizationID, invitationID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvitationInvalid
	}
	return &record, err
}

func (r *Repository) RevokeOrganizationInvitation(
	ctx context.Context,
	organizationID string,
	invitationID string,
	now time.Time,
) error {
	result, err := r.db.ExecContext(ctx, `
UPDATE organization_invitations SET revoked_at = `+r.bind(1)+`, updated_at = `+r.bind(2)+`
WHERE organization_id = `+r.bind(3)+` AND invitation_id = `+r.bind(4)+`
  AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > `+r.bind(5),
		now, now, organizationID, invitationID, now,
	)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrInvitationInvalid
	}
	return nil
}

// DeleteOrganizationInvitation 在同一语句中限定租户和终态，避免先查后删的竞态。
func (r *Repository) DeleteOrganizationInvitation(ctx context.Context, organizationID, invitationID string, now time.Time) error {
	result, err := r.db.ExecContext(ctx, `
DELETE FROM organization_invitations
WHERE organization_id = `+r.bind(1)+` AND invitation_id = `+r.bind(2)+`
  AND (accepted_at IS NOT NULL OR revoked_at IS NOT NULL OR expires_at <= `+r.bind(3)+`)`,
		organizationID, invitationID, now)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrInvitationInvalid
	}
	return nil
}

func (r *Repository) AcceptOrganizationInvitation(
	ctx context.Context,
	input AcceptOrganizationInvitationRecord,
) (*DeploymentMemberRecord, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	invitation, err := scanOrganizationInvitation(tx.QueryRowContext(ctx, invitationSelect+`
WHERE i.token_hash = `+r.bind(1), input.TokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvitationInvalid
	}
	if err != nil {
		return nil, err
	}
	if invitation.AcceptedAt != nil || invitation.RevokedAt != nil || !invitation.ExpiresAt.After(input.AcceptedAt) {
		return nil, ErrInvitationInvalid
	}
	if err = r.lockDeployment(ctx, tx, invitation.DeploymentID); err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO users (user_id, username, display_name, status, created_at, updated_at)
VALUES (`+r.dialect.BindList(6)+`) ON CONFLICT(username) DO NOTHING`,
		input.UserID, input.Username, input.DisplayName, "active", input.AcceptedAt, input.AcceptedAt,
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
		{`INSERT INTO identities (identity_id, user_id, provider, subject, created_at, updated_at) VALUES (` + r.dialect.BindList(6) + `)`, []any{input.IdentityID, input.UserID, "password", input.Username, input.AcceptedAt, input.AcceptedAt}},
		{`INSERT INTO password_credentials (credential_id, user_id, password_hash, password_algo, password_updated_at, created_at, updated_at) VALUES (` + r.dialect.BindList(7) + `)`, []any{input.CredentialID, input.UserID, input.PasswordHash, "argon2id", input.AcceptedAt, input.AcceptedAt, input.AcceptedAt}},
		{`INSERT INTO deployment_memberships (deployment_id, user_id, role, status, created_at, updated_at) VALUES (` + r.dialect.BindList(6) + `)`, []any{invitation.DeploymentID, input.UserID, invitation.Role, "active", input.AcceptedAt, input.AcceptedAt}},
		{`INSERT INTO organization_memberships (organization_id, user_id, role, status, created_at, updated_at) VALUES (` + r.dialect.BindList(6) + `)`, []any{invitation.OrganizationID, input.UserID, invitation.Role, "active", input.AcceptedAt, input.AcceptedAt}},
	}
	for _, statement := range statements {
		if _, err = tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return nil, err
		}
	}
	result, err = tx.ExecContext(ctx, `
UPDATE organization_invitations
SET accepted_by_user_id = `+r.bind(1)+`, accepted_at = `+r.bind(2)+`, updated_at = `+r.bind(3)+`
WHERE invitation_id = `+r.bind(4)+` AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > `+r.bind(5),
		input.UserID, input.AcceptedAt, input.AcceptedAt, invitation.InvitationID, input.AcceptedAt,
	)
	if err != nil {
		return nil, err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return nil, ErrInvitationInvalid
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &DeploymentMemberRecord{
		DeploymentID: invitation.DeploymentID, UserID: input.UserID,
		Username: input.Username, DisplayName: input.DisplayName, Role: invitation.Role,
		MembershipStatus: "active", CreatedAt: input.AcceptedAt, UpdatedAt: input.AcceptedAt,
	}, nil
}

const invitationSelect = `
SELECT i.invitation_id, o.deployment_id, i.organization_id, o.name, i.token_hash, i.role,
       i.created_by_user_id, i.accepted_by_user_id, i.expires_at, i.accepted_at,
       i.revoked_at, i.created_at, i.updated_at
FROM organization_invitations i
JOIN organizations o ON o.organization_id = i.organization_id AND o.status = 'active'
JOIN deployments d ON d.deployment_id = o.deployment_id AND d.status = 'active'
`

func scanOrganizationInvitation(row rowScanner) (OrganizationInvitationRecord, error) {
	var record OrganizationInvitationRecord
	var acceptedBy sql.NullString
	var acceptedAt, revokedAt sql.NullTime
	err := row.Scan(
		&record.InvitationID, &record.DeploymentID, &record.OrganizationID,
		&record.OrganizationName, &record.TokenHash, &record.Role,
		&record.CreatedByUserID, &acceptedBy, &record.ExpiresAt, &acceptedAt,
		&revokedAt, &record.CreatedAt, &record.UpdatedAt,
	)
	record.AcceptedByUserID = acceptedBy.String
	record.AcceptedAt = nullTimePointer(acceptedAt)
	record.RevokedAt = nullTimePointer(revokedAt)
	record.ExpiresAt = record.ExpiresAt.UTC()
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, err
}
