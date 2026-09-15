package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (r *Repository) ListOwnedAgents(ctx context.Context, deploymentID, organizationID, ownerUserID string) ([]AgentRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT agent_id, deployment_id, organization_id, owner_user_id, source_agent_id,
       name, avatar, status, created_at, updated_at
FROM agents
WHERE deployment_id = `+r.bind(1)+` AND organization_id = `+r.bind(2)+`
  AND owner_user_id = `+r.bind(3)+` AND status = 'active' AND `+activeAgentOwner+`
ORDER BY name, agent_id`, deploymentID, organizationID, ownerUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]AgentRecord, 0)
	for rows.Next() {
		record, scanErr := scanAgent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (r *Repository) ListOrganizationAgents(ctx context.Context, deploymentID, organizationID string) ([]AgentRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT agent_id, deployment_id, organization_id, owner_user_id, source_agent_id,
       name, avatar, status, created_at, updated_at
FROM agents
WHERE deployment_id = `+r.bind(1)+` AND organization_id = `+r.bind(2)+` AND status = 'active' AND `+activeAgentOwner+`
ORDER BY name, agent_id`, deploymentID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]AgentRecord, 0)
	for rows.Next() {
		record, scanErr := scanAgent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (r *Repository) UpsertOwnedAgent(ctx context.Context, record AgentRecord, now time.Time) (AgentRecord, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return AgentRecord{}, err
	}
	defer tx.Rollback()
	// 与成员撤权共用部署锁，过期的请求不能在撤权提交后重新发布身份。
	if err = r.lockDeployment(ctx, tx, record.DeploymentID); err != nil {
		return AgentRecord{}, err
	}
	var active int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM organization_memberships om
		JOIN organizations o ON o.organization_id = om.organization_id
		JOIN deployment_memberships dm ON dm.deployment_id = o.deployment_id AND dm.user_id = om.user_id
		JOIN users u ON u.user_id = om.user_id
		WHERE o.deployment_id = `+r.bind(1)+` AND om.organization_id = `+r.bind(2)+` AND om.user_id = `+r.bind(3)+`
		AND o.status = 'active' AND om.status = 'active' AND dm.status = 'active' AND u.status = 'active'`,
		record.DeploymentID, record.OrganizationID, record.OwnerUserID).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return AgentRecord{}, ErrNotFound
	}
	if err != nil {
		return AgentRecord{}, err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO agents
    (agent_id, deployment_id, organization_id, owner_user_id, source_agent_id,
     name, avatar, status, created_at, updated_at)
VALUES (`+r.dialect.BindList(10)+`)
ON CONFLICT (deployment_id, organization_id, owner_user_id, source_agent_id) DO UPDATE SET
    name = excluded.name, avatar = excluded.avatar, status = 'active', updated_at = excluded.updated_at`,
		record.AgentID, record.DeploymentID, record.OrganizationID, record.OwnerUserID,
		record.SourceAgentID, record.Name, nullableString(record.Avatar), "active", now, now)
	if err != nil {
		return AgentRecord{}, err
	}
	result, err := scanAgent(tx.QueryRowContext(ctx, `
SELECT agent_id, deployment_id, organization_id, owner_user_id, source_agent_id,
       name, avatar, status, created_at, updated_at
FROM agents
WHERE deployment_id = `+r.bind(1)+` AND organization_id = `+r.bind(2)+`
  AND owner_user_id = `+r.bind(3)+` AND source_agent_id = `+r.bind(4),
		record.DeploymentID, record.OrganizationID, record.OwnerUserID, record.SourceAgentID))
	if err != nil {
		return AgentRecord{}, err
	}
	return result, tx.Commit()
}

func (r *Repository) ListVerifiedAgents(ctx context.Context, deploymentID, organizationID, ownerUserID string, agentIDs []string) ([]AgentRecord, error) {
	// ponytail: 首版最多 100 个 Agent，逐项查询保留 SQLite/PostgreSQL 共用 SQL；批量建群成为热点时改为方言化 IN 查询。
	result := make([]AgentRecord, 0, len(agentIDs))
	for _, agentID := range agentIDs {
		record, err := scanAgent(r.db.QueryRowContext(ctx, `
SELECT agent_id, deployment_id, organization_id, owner_user_id, source_agent_id,
       name, avatar, status, created_at, updated_at
FROM agents
WHERE deployment_id = `+r.bind(1)+` AND organization_id = `+r.bind(2)+`
  AND owner_user_id = `+r.bind(3)+` AND agent_id = `+r.bind(4)+` AND status = 'active' AND `+activeAgentOwner,
			deploymentID, organizationID, ownerUserID, agentID))
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, nil
}

// Agent 公开身份不能延长其真人所有者的组织或部署访问资格。
const activeAgentOwner = `EXISTS (
 SELECT 1 FROM organization_memberships om
 JOIN organizations o ON o.organization_id = om.organization_id
 JOIN deployment_memberships dm ON dm.deployment_id = o.deployment_id AND dm.user_id = om.user_id
 JOIN users u ON u.user_id = om.user_id
 WHERE om.organization_id = agents.organization_id AND om.user_id = agents.owner_user_id
   AND o.deployment_id = agents.deployment_id
   AND om.status = 'active' AND o.status = 'active' AND dm.status = 'active' AND u.status = 'active'
)`

func scanAgent(row rowScanner) (AgentRecord, error) {
	var record AgentRecord
	var avatar sql.NullString
	err := row.Scan(&record.AgentID, &record.DeploymentID, &record.OrganizationID,
		&record.OwnerUserID, &record.SourceAgentID, &record.Name, &avatar,
		&record.Status, &record.CreatedAt, &record.UpdatedAt)
	record.Avatar = avatar.String
	record.CreatedAt, record.UpdatedAt = record.CreatedAt.UTC(), record.UpdatedAt.UTC()
	return record, err
}

// ScanAgent 读取跨存储边界的 Agent 行，供 Control 快照导入复用。
func ScanAgent(row interface{ Scan(...any) error }) (AgentRecord, error) {
	return scanAgent(row)
}
