package auth

import (
	"context"
	"errors"
	"strings"

	store "github.com/nexus-research-lab/nexus-control/internal/storage/auth"
)

// ListOwnedAgents 返回当前真人已发布的 active Agent 身份。
func (s *Service) ListOwnedAgents(ctx context.Context, actor Principal) ([]Agent, error) {
	records, err := s.repository.ListOwnedAgents(ctx, actor.DeploymentID, actor.OrganizationID, actor.UserID)
	if err != nil {
		return nil, err
	}
	result := make([]Agent, 0, len(records))
	for _, record := range records {
		result = append(result, agentFromRecord(record))
	}
	return result, nil
}

// ListOrganizationAgents 返回当前组织内 active Agent 的公开目录。
func (s *Service) ListOrganizationAgents(ctx context.Context, actor Principal) ([]AgentDirectoryEntry, error) {
	records, err := s.repository.ListOrganizationAgents(ctx, actor.DeploymentID, actor.OrganizationID)
	if err != nil {
		return nil, err
	}
	result := make([]AgentDirectoryEntry, 0, len(records))
	for _, record := range records {
		result = append(result, AgentDirectoryEntry{
			AgentID: record.AgentID, OwnerUserID: record.OwnerUserID,
			Name: record.Name, Avatar: record.Avatar,
		})
	}
	return result, nil
}

// PublishAgent 创建或刷新当前真人拥有的本地 Agent 在线身份。
func (s *Service) PublishAgent(ctx context.Context, actor Principal, input PublishAgentInput) (Agent, error) {
	input.SourceAgentID = strings.TrimSpace(input.SourceAgentID)
	input.Name = strings.TrimSpace(input.Name)
	input.Avatar = strings.TrimSpace(input.Avatar)
	if input.SourceAgentID == "" || len(input.SourceAgentID) > 128 || input.Name == "" || len(input.Name) > 128 || len(input.Avatar) > 2048 {
		return Agent{}, ErrRequestInvalid
	}
	record, err := s.repository.UpsertOwnedAgent(ctx, store.AgentRecord{
		AgentID: newID("agent"), DeploymentID: actor.DeploymentID,
		OrganizationID: actor.OrganizationID, OwnerUserID: actor.UserID,
		SourceAgentID: input.SourceAgentID, Name: input.Name, Avatar: input.Avatar,
	}, s.now())
	if errors.Is(err, store.ErrNotFound) {
		return Agent{}, ErrForbidden
	}
	if err != nil {
		return Agent{}, err
	}
	return agentFromRecord(record), nil
}

// VerifyOwnedAgents 验证一组 Control Agent 都处于当前组织且归请求真人所有。
func (s *Service) VerifyOwnedAgents(ctx context.Context, deploymentID, organizationID, ownerUserID string, agentIDs []string) ([]Agent, error) {
	deploymentID = strings.TrimSpace(deploymentID)
	organizationID = strings.TrimSpace(organizationID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	if deploymentID == "" || organizationID == "" || ownerUserID == "" || len(agentIDs) == 0 || len(agentIDs) > 100 {
		return nil, ErrRequestInvalid
	}
	normalized := make([]string, 0, len(agentIDs))
	seen := make(map[string]struct{}, len(agentIDs))
	for _, agentID := range agentIDs {
		agentID = strings.TrimSpace(agentID)
		if agentID == "" || len(agentID) > 128 {
			return nil, ErrRequestInvalid
		}
		if _, ok := seen[agentID]; ok {
			continue
		}
		seen[agentID] = struct{}{}
		normalized = append(normalized, agentID)
	}
	records, err := s.repository.ListVerifiedAgents(ctx, deploymentID, organizationID, ownerUserID, normalized)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrForbidden
	}
	if err != nil {
		return nil, err
	}
	result := make([]Agent, 0, len(records))
	for _, record := range records {
		result = append(result, agentFromRecord(record))
	}
	return result, nil
}

func agentFromRecord(record store.AgentRecord) Agent {
	return Agent{AgentID: record.AgentID, OwnerUserID: record.OwnerUserID,
		SourceAgentID: record.SourceAgentID, Name: record.Name, Avatar: record.Avatar,
		Status: record.Status, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt}
}
