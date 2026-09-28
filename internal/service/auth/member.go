package auth

import (
	"context"
	"errors"
	"strings"

	store "github.com/nexus-research-lab/nexus-control/internal/storage/auth"
)

// ListMembers 返回当前 Organization 的成员。
func (s *Service) ListMembers(ctx context.Context, actor Principal) ([]DeploymentMember, error) {
	if actor.OrganizationID == "" {
		return nil, ErrForbidden
	}
	records, err := s.repository.ListMembers(ctx, actor.DeploymentID, actor.OrganizationID)
	if err != nil {
		return nil, err
	}
	members := make([]DeploymentMember, 0, len(records))
	for _, record := range records {
		members = append(members, memberFromRecord(record))
	}
	return members, nil
}

// ListMemberDirectory 返回当前组织可邀请的 active 真人成员。
func (s *Service) ListMemberDirectory(ctx context.Context, actor Principal) ([]MemberDirectoryEntry, error) {
	records, err := s.repository.ListActiveMembers(ctx, actor.DeploymentID, actor.OrganizationID)
	if err != nil {
		return nil, err
	}
	members := make([]MemberDirectoryEntry, 0, len(records))
	for _, record := range records {
		members = append(members, MemberDirectoryEntry{
			UserID: record.UserID, Username: record.Username,
			DisplayName: record.DisplayName, Avatar: record.Avatar,
		})
	}
	return members, nil
}

// VerifyOrganizationMembers 确认一组真人都属于指定 Deployment 下的同一 active Organization。
func (s *Service) VerifyOrganizationMembers(
	ctx context.Context,
	deploymentID string,
	organizationID string,
	userIDs []string,
) error {
	deploymentID = strings.TrimSpace(deploymentID)
	organizationID = strings.TrimSpace(organizationID)
	if deploymentID == "" || organizationID == "" || len(userIDs) > 100 {
		return ErrRequestInvalid
	}
	records, err := s.repository.ListActiveMembers(ctx, deploymentID, organizationID)
	if err != nil {
		return err
	}
	active := make(map[string]struct{}, len(records))
	for _, record := range records {
		active[record.UserID] = struct{}{}
	}
	for _, userID := range userIDs {
		userID = strings.TrimSpace(userID)
		if userID == "" || len(userID) > 128 {
			return ErrRequestInvalid
		}
		if _, ok := active[userID]; !ok {
			return ErrForbidden
		}
	}
	return nil
}

// UpdateMember 更新成员角色或状态。
func (s *Service) UpdateMember(ctx context.Context, actor Principal, userID string, input UpdateMemberInput) (*DeploymentMember, error) {
	if actor.OrganizationRole != RoleOwner && actor.OrganizationRole != RoleAdmin {
		return nil, ErrForbidden
	}
	userID = strings.TrimSpace(userID)
	if userID == "" || (input.Role == nil && input.Status == nil && input.DisplayName == nil) {
		return nil, ErrRequestInvalid
	}
	target, err := s.repository.MemberByID(ctx, actor.DeploymentID, actor.OrganizationID, userID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if input.ExpectedVersion != nil && *input.ExpectedVersion != target.UpdatedAt.UnixMicro() {
		return nil, ErrConflict
	}
	nextName := target.DisplayName
	if input.DisplayName != nil {
		nextName = strings.TrimSpace(*input.DisplayName)
		if nextName == "" || len(nextName) > 128 {
			return nil, ErrRequestInvalid
		}
	}
	nextRole, nextStatus := target.Role, target.MembershipStatus
	if target.MembershipStatus != MembershipActive || target.Role == RoleOwner {
		return nil, ErrForbidden
	}
	if input.Role != nil {
		nextRole, err = normalizeRole(*input.Role)
		if err != nil {
			return nil, errors.Join(ErrRequestInvalid, err)
		}
		if nextRole == RoleOwner || target.Role == RoleOwner {
			return nil, ErrForbidden
		}
	}
	if input.Status != nil {
		nextStatus = strings.TrimSpace(*input.Status)
		if nextStatus != MembershipActive && nextStatus != MembershipRevoked {
			return nil, errors.Join(ErrRequestInvalid, errors.New("status 仅支持 active 或 revoked"))
		}
	}
	if actor.OrganizationRole == RoleAdmin && (target.Role != RoleMember || nextRole != RoleMember) {
		return nil, ErrForbidden
	}
	if actor.UserID == target.UserID && nextStatus == MembershipRevoked {
		return nil, errors.Join(ErrConflict, errors.New("不能停用当前登录账号"))
	}
	record, err := s.repository.UpdateMember(
		ctx, actor.DeploymentID, actor.OrganizationID, userID, actor.UserID,
		target.Role, target.MembershipStatus, target.UpdatedAt.UnixMicro(),
		nextRole, nextStatus, nextName, s.now(),
	)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if errors.Is(err, store.ErrLastOwner) || errors.Is(err, store.ErrStateConflict) {
		return nil, errors.Join(ErrConflict, err)
	}
	if err != nil {
		return nil, err
	}
	member := memberFromRecord(*record)
	return &member, nil
}

func memberFromRecord(record store.DeploymentMemberRecord) DeploymentMember {
	return DeploymentMember{
		DeploymentID: record.DeploymentID, UserID: record.UserID,
		Username: record.Username, DisplayName: record.DisplayName,
		Role: record.Role, MembershipStatus: record.MembershipStatus,
		WebAccessDisabled: record.WebAccessDisabled, Avatar: record.Avatar, LastLoginAt: record.LastLoginAt,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
}
