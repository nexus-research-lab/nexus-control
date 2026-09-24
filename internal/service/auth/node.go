package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"

	store "github.com/nexus-research-lab/nexus-control/internal/storage/auth"
)

const relayNodeAudience = "nexus-relay-node"

const nodeTokenTTL = 15 * time.Minute

// ExecutionNode 是用户可查看和撤销的设备执行授权；凭据从不回显。
type ExecutionNode struct {
	NodeID    string     `json:"node_id"`
	Name      string     `json:"name"`
	AgentIDs  []string   `json:"agent_ids"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

type RegisterNodeInput struct {
	NodeID     string   `json:"node_id"`
	Name       string   `json:"name"`
	Credential string   `json:"credential"`
	AgentIDs   []string `json:"agent_ids"`
}

type NodeTokenResult struct {
	Token     string                `json:"token"`
	ExpiresAt time.Time             `json:"expires_at"`
	Agents    []Agent               `json:"agents"`
	Directory []AgentDirectoryEntry `json:"directory,omitempty"`
}

func nodeCredentialHash(credential string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil || len(decoded) != 32 {
		return "", ErrRequestInvalid
	}
	sum := sha256.Sum256(decoded)
	return hex.EncodeToString(sum[:]), nil
}

func executionNode(record store.NodeRecord) ExecutionNode {
	return ExecutionNode{NodeID: record.NodeID, Name: record.Name, AgentIDs: record.AgentIDs, CreatedAt: record.CreatedAt, RevokedAt: record.RevokedAt}
}

func (s *Service) RegisterNode(ctx context.Context, actor Principal, input RegisterNodeInput) (ExecutionNode, error) {
	input.Name = strings.TrimSpace(input.Name)
	if !validNodeID(input.NodeID) || input.Name == "" || len(input.Name) > 128 || len(input.AgentIDs) == 0 || len(input.AgentIDs) > 32 {
		return ExecutionNode{}, ErrRequestInvalid
	}
	hash, err := nodeCredentialHash(input.Credential)
	if err != nil {
		return ExecutionNode{}, err
	}
	ids := slices.Clone(input.AgentIDs)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	for _, id := range ids {
		if id == "" || len(id) > 128 {
			return ExecutionNode{}, ErrRequestInvalid
		}
	}
	record, err := s.repository.RegisterNode(ctx, store.NodeRecord{NodeID: input.NodeID, Name: input.Name, CredentialHash: hash, AgentIDs: ids, DeploymentID: actor.DeploymentID, OrganizationID: actor.OrganizationID, OwnerUserID: actor.UserID, ParentSessionID: actor.SessionID, CreatedAt: s.now()})
	if errors.Is(err, store.ErrNotFound) {
		return ExecutionNode{}, ErrForbidden
	}
	if errors.Is(err, store.ErrStateConflict) {
		return ExecutionNode{}, ErrConflict
	}
	return executionNode(record), err
}

func (s *Service) ListNodes(ctx context.Context, actor Principal) ([]ExecutionNode, error) {
	records, err := s.repository.ListNodes(ctx, actor.DeploymentID, actor.OrganizationID, actor.UserID)
	result := make([]ExecutionNode, 0, len(records))
	for _, record := range records {
		result = append(result, executionNode(record))
	}
	return result, err
}

func (s *Service) RevokeNode(ctx context.Context, actor Principal, nodeID string) error {
	if !validNodeID(nodeID) {
		return ErrRequestInvalid
	}
	err := s.repository.RevokeNode(ctx, actor.DeploymentID, actor.OrganizationID, actor.UserID, actor.SessionID, nodeID, s.now())
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

func validNodeID(id string) bool {
	return id != "" && len(id) <= 128 && !strings.ContainsAny(id, ":/") && !strings.ContainsFunc(id, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

func (s *Service) Node(ctx context.Context, actor Principal, nodeID string) (ExecutionNode, error) {
	record, err := s.repository.Node(ctx, actor.DeploymentID, actor.OrganizationID, actor.UserID, nodeID)
	if errors.Is(err, store.ErrNotFound) {
		return ExecutionNode{}, ErrNotFound
	}
	return executionNode(record), err
}

// ExchangeNodeToken 只接受独立设备凭据；普通浏览器 exchange 仍拒绝 Node audience。
func (s *Service) ExchangeNodeToken(ctx context.Context, credential string) (NodeTokenResult, error) {
	return s.ExchangeNodeTokenWithDirectory(ctx, credential, nil)
}

// ExchangeNodeTokenWithDirectory 仅补充当前组织公开身份，不授予远端 Agent 执行权。
func (s *Service) ExchangeNodeTokenWithDirectory(ctx context.Context, credential string, agentIDs []string) (NodeTokenResult, error) {
	if len(agentIDs) > 100 {
		return NodeTokenResult{}, ErrRequestInvalid
	}
	now := s.now()
	hash, err := nodeCredentialHash(credential)
	if err != nil {
		return NodeTokenResult{}, ErrUnauthenticated
	}
	node, err := s.repository.NodeByCredential(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return NodeTokenResult{}, ErrUnauthenticated
	}
	if err != nil {
		return NodeTokenResult{}, err
	}
	record, err := s.repository.ResolveNodeOwner(ctx, node)
	if err != nil {
		return NodeTokenResult{}, err
	}
	if record == nil {
		return NodeTokenResult{}, ErrUnauthenticated
	}
	actor := principalFromRecord(*record)
	if actor.DeploymentID != node.DeploymentID || actor.OrganizationID != node.OrganizationID {
		return NodeTokenResult{}, ErrForbidden
	}
	agents, err := s.VerifyOwnedAgents(ctx, node.DeploymentID, node.OrganizationID, node.OwnerUserID, node.AgentIDs)
	if err != nil {
		return NodeTokenResult{}, err
	}
	var directory []AgentDirectoryEntry
	if len(agentIDs) > 0 {
		entries, err := s.ListOrganizationAgents(ctx, actor)
		if err != nil {
			return NodeTokenResult{}, err
		}
		for _, entry := range entries {
			if slices.Contains(agentIDs, entry.AgentID) {
				directory = append(directory, entry)
			}
		}
	}
	actor.ParentSessionID, actor.SessionID, actor.NodeID = actor.SessionID, "node:"+node.NodeID, node.NodeID
	actor.Role, actor.AuthMethod, actor.AgentIDs = "node", "node", node.AgentIDs
	token, err := s.signer.Sign(actor, relayNodeAudience, now, nodeTokenTTL)
	return NodeTokenResult{Token: token, ExpiresAt: now.Add(nodeTokenTTL), Agents: agents, Directory: directory}, err
}
