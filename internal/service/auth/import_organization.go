package auth

import (
	"context"
	"database/sql"
	store "github.com/nexus-research-lab/nexus-control/internal/storage/auth"
)

// scanControlOrganizations 保留多组织、历史成员关系与邀请，不能从平台角色推导组织角色。
func scanControlOrganizations(ctx context.Context, source *sql.Tx, deployment *store.ImportedDeploymentRecord) error {
	rows, err := source.QueryContext(ctx, `SELECT organization_id,name,status,created_at,updated_at FROM organizations WHERE deployment_id=? ORDER BY organization_id`, deployment.DeploymentID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item store.ImportedOrganizationRecord
		if err = rows.Scan(&item.ID, &item.Name, &item.Status, &item.CreatedAt, &item.UpdatedAt); err != nil {
			rows.Close()
			return err
		}
		deployment.Organizations = append(deployment.Organizations, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = source.QueryContext(ctx, `SELECT om.organization_id,om.user_id,om.role,om.status,om.created_at,om.updated_at FROM organization_memberships om JOIN organizations o ON o.organization_id=om.organization_id WHERE o.deployment_id=?`, deployment.DeploymentID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item store.ImportedOrganizationMembership
		if err = rows.Scan(&item.OrganizationID, &item.UserID, &item.Role, &item.Status, &item.CreatedAt, &item.UpdatedAt); err != nil {
			rows.Close()
			return err
		}
		deployment.OrganizationMemberships = append(deployment.OrganizationMemberships, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = source.QueryContext(ctx, `SELECT i.invitation_id,i.organization_id,i.token_hash,i.role,i.created_by_user_id,COALESCE(i.accepted_by_user_id,''),i.expires_at,i.accepted_at,i.revoked_at,i.created_at,i.updated_at FROM organization_invitations i JOIN organizations o ON o.organization_id=i.organization_id WHERE o.deployment_id=?`, deployment.DeploymentID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item store.OrganizationInvitationRecord
		var accepted, revoked sql.NullTime
		if err = rows.Scan(&item.InvitationID, &item.OrganizationID, &item.TokenHash, &item.Role, &item.CreatedByUserID, &item.AcceptedByUserID, &item.ExpiresAt, &accepted, &revoked, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return err
		}
		if accepted.Valid {
			item.AcceptedAt = &accepted.Time
		}
		if revoked.Valid {
			item.RevokedAt = &revoked.Time
		}
		deployment.Invitations = append(deployment.Invitations, item)
	}
	return rows.Err()
}
