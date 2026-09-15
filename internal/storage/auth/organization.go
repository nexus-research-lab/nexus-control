package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// OrganizationCommand 的身份来自 Session，事务内再次校验当前成员关系。
type OrganizationCommand struct {
	Actor                                                 PrincipalRecord
	Action, OrganizationID, Name, TargetUserID, TokenHash string
	Now                                                   time.Time
}

// MutateOrganization 串行化组织关系与撤权事件，账号和部署访问不随组织退出而删除。
func (r *Repository) MutateOrganization(ctx context.Context, c OrganizationCommand) error {
	tx, err := r.beginIdentityWrite(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var active int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM deployment_memberships m JOIN users u ON u.user_id=m.user_id JOIN deployments d ON d.deployment_id=m.deployment_id WHERE m.deployment_id=`+r.bind(1)+` AND m.user_id=`+r.bind(2)+` AND m.status='active' AND u.status='active' AND d.status='active'`, c.Actor.DeploymentID, c.Actor.UserID).Scan(&active); err != nil {
		return err
	}
	if active != 1 {
		return ErrStateConflict
	}
	var org, role string
	err = tx.QueryRowContext(ctx, `SELECT om.organization_id, om.role FROM organization_memberships om JOIN organizations o ON o.organization_id=om.organization_id WHERE om.user_id=`+r.bind(1)+` AND o.deployment_id=`+r.bind(2)+` AND om.status='active' AND o.status='active'`, c.Actor.UserID, c.Actor.DeploymentID).Scan(&org, &role)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if c.Action == "create" || c.Action == "join" {
		if org != "" {
			return ErrStateConflict
		}
	} else if org == "" || org != c.Actor.OrganizationID {
		return ErrStateConflict
	}
	switch c.Action {
	case "create":
		org = c.OrganizationID
		_, err = tx.ExecContext(ctx, `INSERT INTO organizations (organization_id,deployment_id,name,status,created_at,updated_at) VALUES (`+r.dialect.BindList(6)+`)`, c.OrganizationID, c.Actor.DeploymentID, c.Name, "active", c.Now, c.Now)
		if err == nil {
			err = r.joinOrganization(ctx, tx, c.OrganizationID, c.Actor.UserID, "owner", c.Now)
		}
	case "join":
		var invitationID, invitedOrg, invitedRole string
		err = tx.QueryRowContext(ctx, `SELECT i.invitation_id,i.organization_id,i.role FROM organization_invitations i JOIN organizations o ON o.organization_id=i.organization_id WHERE i.token_hash=`+r.bind(1)+` AND o.deployment_id=`+r.bind(2)+` AND o.status='active' AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at>`+r.bind(3), c.TokenHash, c.Actor.DeploymentID, c.Now).Scan(&invitationID, &invitedOrg, &invitedRole)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvitationInvalid
		}
		if err != nil {
			return err
		}
		if err = r.joinOrganization(ctx, tx, invitedOrg, c.Actor.UserID, invitedRole, c.Now); err != nil {
			return err
		}
		org = invitedOrg
		_, err = tx.ExecContext(ctx, `UPDATE organization_invitations SET accepted_by_user_id=`+r.bind(1)+`,accepted_at=`+r.bind(2)+`,updated_at=`+r.bind(3)+` WHERE invitation_id=`+r.bind(4), c.Actor.UserID, c.Now, c.Now, invitationID)
	case "leave":
		if role == "owner" {
			return ErrLastOwner
		}
		err = r.revokeOrganizationMember(ctx, tx, c.Actor.DeploymentID, org, c.Actor.UserID, c.Now)
	case "transfer":
		if role != "owner" || c.TargetUserID == c.Actor.UserID {
			return ErrStateConflict
		}
		var targetRole string
		if err = tx.QueryRowContext(ctx, `SELECT om.role FROM organization_memberships om JOIN users u ON u.user_id=om.user_id JOIN deployment_memberships dm ON dm.user_id=om.user_id WHERE om.organization_id=`+r.bind(1)+` AND om.user_id=`+r.bind(2)+` AND dm.deployment_id=`+r.bind(3)+` AND om.status='active' AND u.status='active' AND dm.status='active'`, org, c.TargetUserID, c.Actor.DeploymentID).Scan(&targetRole); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrStateConflict
			}
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE organization_memberships SET role='admin',updated_at=`+r.bind(1)+` WHERE organization_id=`+r.bind(2)+` AND user_id=`+r.bind(3), c.Now, org, c.Actor.UserID)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE organization_memberships SET role='owner',updated_at=`+r.bind(1)+` WHERE organization_id=`+r.bind(2)+` AND user_id=`+r.bind(3), c.Now, org, c.TargetUserID)
		if err == nil {
			err = r.appendOrganizationInvalidation(ctx, tx, c.Actor.DeploymentID, org, c.TargetUserID, false, c.Now)
		}
	case "rename":
		if role != "owner" && role != "admin" {
			return ErrStateConflict
		}
		_, err = tx.ExecContext(ctx, `UPDATE organizations SET name=`+r.bind(1)+`,updated_at=`+r.bind(2)+` WHERE organization_id=`+r.bind(3), c.Name, c.Now, org)
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO identity_invalidations (deployment_id,user_id,reason,created_at,organization_id) SELECT `+r.bind(1)+`,user_id,'organization_changed',`+r.bind(2)+`,organization_id FROM organization_memberships WHERE organization_id=`+r.bind(3)+` AND status='active'`, c.Actor.DeploymentID, c.Now, org)
		}
	case "dissolve":
		if role != "owner" {
			return ErrStateConflict
		}
		rows, queryErr := tx.QueryContext(ctx, `SELECT user_id FROM organization_memberships WHERE organization_id=`+r.bind(1)+` AND status='active'`, org)
		if queryErr != nil {
			return queryErr
		}
		var users []string
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			users = append(users, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, id := range users {
			if err = r.revokeOrganizationMember(ctx, tx, c.Actor.DeploymentID, org, id, c.Now); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE organizations SET status='disabled',updated_at=`+r.bind(1)+` WHERE organization_id=`+r.bind(2), c.Now, org)
	default:
		return ErrStateConflict
	}
	if err != nil {
		return err
	}
	if c.Action == "create" || c.Action == "join" || c.Action == "transfer" {
		if err = r.appendOrganizationInvalidation(ctx, tx, c.Actor.DeploymentID, org, c.Actor.UserID, false, c.Now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *Repository) joinOrganization(ctx context.Context, tx *sql.Tx, org, user, role string, now time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO organization_memberships (organization_id,user_id,role,status,created_at,updated_at) VALUES (`+r.dialect.BindList(6)+`) ON CONFLICT (organization_id,user_id) DO UPDATE SET role=excluded.role,status='active',updated_at=excluded.updated_at`, org, user, role, "active", now, now)
	return err
}

// requireOrganizationManager 在身份写锁内读取实时组织权限，拒绝已撤权的旧 Principal。
func (r *Repository) requireOrganizationManager(ctx context.Context, tx *sql.Tx, org, user, targetRole string) error {
	var role string
	err := tx.QueryRowContext(ctx, `SELECT om.role FROM organization_memberships om JOIN organizations o ON o.organization_id=om.organization_id JOIN deployment_memberships dm ON dm.deployment_id=o.deployment_id AND dm.user_id=om.user_id JOIN users u ON u.user_id=om.user_id JOIN deployments d ON d.deployment_id=o.deployment_id WHERE om.organization_id=`+r.bind(1)+` AND om.user_id=`+r.bind(2)+` AND om.status='active' AND o.status='active' AND dm.status='active' AND u.status='active' AND d.status='active'`, org, user).Scan(&role)
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

func (r *Repository) revokeOrganizationMember(ctx context.Context, tx *sql.Tx, deployment, org, user string, now time.Time) error {
	for _, query := range []string{
		`UPDATE organization_memberships SET status='revoked',updated_at=` + r.bind(1) + ` WHERE organization_id=` + r.bind(2) + ` AND user_id=` + r.bind(3),
		`UPDATE agents SET status='revoked',updated_at=` + r.bind(1) + ` WHERE organization_id=` + r.bind(2) + ` AND owner_user_id=` + r.bind(3),
		`UPDATE execution_nodes SET revoked_at=` + r.bind(1) + ` WHERE organization_id=` + r.bind(2) + ` AND owner_user_id=` + r.bind(3) + ` AND revoked_at IS NULL`,
	} {
		if _, err := tx.ExecContext(ctx, query, now, org, user); err != nil {
			return err
		}
	}
	return r.appendOrganizationInvalidation(ctx, tx, deployment, org, user, true, now)
}

func (r *Repository) appendOrganizationInvalidation(ctx context.Context, tx *sql.Tx, deployment, org, user string, revoked bool, now time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO identity_invalidations (deployment_id,user_id,reason,created_at,organization_id,membership_revoked) VALUES (`+r.dialect.BindList(6)+`)`, deployment, user, "organization_changed", now, org, revoked)
	return err
}
