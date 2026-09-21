package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// NodeRecord 保存会话授予设备的最小执行范围，不包含本地配置或明文凭据。
type NodeRecord struct {
	NodeID, DeploymentID, OrganizationID, OwnerUserID, ParentSessionID string
	CredentialHash, Name                                               string
	AgentIDs                                                           []string
	CreatedAt                                                          time.Time
	RevokedAt                                                          *time.Time
}

const nodeColumns = `node_id, deployment_id, organization_id, owner_user_id, parent_session_id, credential_hash, name, agent_ids_json, created_at, revoked_at`

func scanNode(row rowScanner) (NodeRecord, error) {
	var node NodeRecord
	var agents string
	var revoked sql.NullTime
	err := row.Scan(&node.NodeID, &node.DeploymentID, &node.OrganizationID, &node.OwnerUserID, &node.ParentSessionID, &node.CredentialHash, &node.Name, &agents, &node.CreatedAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return node, ErrNotFound
	}
	if err != nil {
		return node, err
	}
	node.RevokedAt = nullTimePointer(revoked)
	err = json.Unmarshal([]byte(agents), &node.AgentIDs)
	return node, err
}

func (r *Repository) RegisterNode(ctx context.Context, node NodeRecord) (NodeRecord, error) {
	tx, err := r.beginIdentityWrite(ctx)
	if err != nil {
		return NodeRecord{}, err
	}
	defer tx.Rollback()
	// 会话、成员撤权与注册同序，不能靠进入 HTTP 时的旧 Principal 完成授权。
	var active bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM sessions WHERE session_id = `+r.bind(1)+` AND user_id = `+r.bind(2)+` AND deployment_id = `+r.bind(3)+` AND revoked_at IS NULL AND expires_at > `+r.bind(4)+`)`, node.ParentSessionID, node.OwnerUserID, node.DeploymentID, node.CreatedAt).Scan(&active)
	if err != nil {
		return NodeRecord{}, err
	}
	if !active {
		return NodeRecord{}, ErrNotFound
	}
	for _, id := range node.AgentIDs {
		err = tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM agents WHERE agent_id = `+r.bind(1)+` AND deployment_id = `+r.bind(2)+` AND organization_id = `+r.bind(3)+` AND owner_user_id = `+r.bind(4)+` AND status = 'active' AND `+activeAgentOwner+`)`, id, node.DeploymentID, node.OrganizationID, node.OwnerUserID).Scan(&active)
		if err != nil {
			return NodeRecord{}, err
		}
		if !active {
			return NodeRecord{}, ErrNotFound
		}
	}
	agents, err := json.Marshal(node.AgentIDs)
	if err != nil {
		return NodeRecord{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO execution_nodes (node_id, deployment_id, organization_id, owner_user_id, parent_session_id, credential_hash, name, agent_ids_json, created_at)
		VALUES (`+r.dialect.BindList(9)+`) ON CONFLICT DO NOTHING`, node.NodeID, node.DeploymentID, node.OrganizationID, node.OwnerUserID, node.ParentSessionID, node.CredentialHash, node.Name, string(agents), node.CreatedAt)
	if err != nil {
		return NodeRecord{}, err
	}
	stored, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM execution_nodes WHERE node_id = `+r.bind(1), node.NodeID))
	if errors.Is(err, ErrNotFound) {
		return NodeRecord{}, ErrStateConflict
	}
	if err != nil {
		return NodeRecord{}, err
	}
	oldAgents, err := json.Marshal(stored.AgentIDs)
	if err != nil {
		return NodeRecord{}, err
	}
	if stored.DeploymentID != node.DeploymentID || stored.OrganizationID != node.OrganizationID || stored.OwnerUserID != node.OwnerUserID || stored.ParentSessionID != node.ParentSessionID || stored.Name != node.Name || string(oldAgents) != string(agents) || subtle.ConstantTimeCompare([]byte(stored.CredentialHash), []byte(node.CredentialHash)) != 1 || stored.RevokedAt != nil {
		return NodeRecord{}, ErrStateConflict
	}
	return stored, tx.Commit()
}

func (r *Repository) NodeByCredential(ctx context.Context, hash string) (NodeRecord, error) {
	return scanNode(r.db.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM execution_nodes WHERE credential_hash = `+r.bind(1)+` AND revoked_at IS NULL`, hash))
}

// 改密属于安全失效，必须持久撤销设备，不能只让已有短令牌到期。
func (r *Repository) revokeUserNodes(ctx context.Context, tx *sql.Tx, userID string, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `UPDATE execution_nodes SET revoked_at=`+r.bind(1)+` WHERE owner_user_id=`+r.bind(2)+` AND revoked_at IS NULL RETURNING deployment_id,node_id`, now, userID)
	if err != nil {
		return err
	}
	type revokedNode struct{ deployment, id string }
	var nodes []revokedNode
	for rows.Next() {
		var node revokedNode
		if err = rows.Scan(&node.deployment, &node.id); err != nil {
			rows.Close()
			return err
		}
		nodes = append(nodes, node)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, node := range nodes {
		if err = r.appendIdentityInvalidation(ctx, tx, node.deployment, userID, "node:"+node.id, "session_revoked", now); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) ListNodes(ctx context.Context, deploymentID, organizationID, ownerID string) ([]NodeRecord, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+nodeColumns+` FROM execution_nodes WHERE deployment_id = `+r.bind(1)+` AND organization_id = `+r.bind(2)+` AND owner_user_id = `+r.bind(3)+` ORDER BY created_at DESC LIMIT 100`, deploymentID, organizationID, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes := make([]NodeRecord, 0)
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, rows.Err()
}

func (r *Repository) Node(ctx context.Context, deploymentID, organizationID, ownerID, nodeID string) (NodeRecord, error) {
	return scanNode(r.db.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM execution_nodes WHERE node_id = `+r.bind(1)+` AND deployment_id = `+r.bind(2)+` AND organization_id = `+r.bind(3)+` AND owner_user_id = `+r.bind(4), nodeID, deploymentID, organizationID, ownerID))
}

func (r *Repository) RevokeNode(ctx context.Context, deploymentID, organizationID, ownerID, sessionID, nodeID string, now time.Time) error {
	tx, err := r.beginIdentityWrite(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// 撤销和注册同序；未知注册也先落终止记录，禁止迟到注册恢复授权。
	// 保留前缀不可能是 SHA-256 凭据哈希，因此该记录从未拥有机器能力。
	_, err = tx.ExecContext(ctx, `INSERT INTO execution_nodes (node_id, deployment_id, organization_id, owner_user_id, parent_session_id, credential_hash, name, agent_ids_json, created_at, revoked_at)
		SELECT `+r.dialect.BindList(10)+` WHERE EXISTS (SELECT 1 FROM sessions WHERE session_id = `+r.bind(11)+` AND user_id = `+r.bind(12)+` AND deployment_id = `+r.bind(13)+` AND revoked_at IS NULL AND expires_at > `+r.bind(14)+`) ON CONFLICT DO NOTHING`, nodeID, deploymentID, organizationID, ownerID, sessionID, "revoked:"+nodeID, "Revoked", "[]", now, now, sessionID, ownerID, deploymentID, now)
	if err != nil {
		return err
	}
	node, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM execution_nodes WHERE node_id = `+r.bind(1)+` AND deployment_id = `+r.bind(2)+` AND organization_id = `+r.bind(3)+` AND owner_user_id = `+r.bind(4), nodeID, deploymentID, organizationID, ownerID))
	if err != nil {
		return err
	}
	if node.RevokedAt != nil {
		return tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, `UPDATE execution_nodes SET revoked_at = `+r.bind(1)+` WHERE node_id = `+r.bind(2), now, nodeID); err != nil {
		return err
	}
	// 复用精确 Session 撤权语义，只撤销节点能力，不使真人浏览器登出。
	if err = r.appendIdentityInvalidation(ctx, tx, deploymentID, ownerID, "node:"+nodeID, "session_revoked", now); err != nil {
		return err
	}
	return tx.Commit()
}
