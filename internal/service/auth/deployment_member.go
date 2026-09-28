// INPUT: 已验证的平台 Principal 与部署用户操作。
// OUTPUT: 无需组织身份的 Web 账号管理。
// POS: 平台用户边界；组织治理保持在 member.go。
package auth

import (
	"context"
	"errors"
	"strings"

	store "github.com/nexus-research-lab/nexus-control/internal/storage/auth"
)

// ListDeploymentMembers 返回当前 Deployment 的成员。
func (s *Service) ListDeploymentMembers(ctx context.Context, actor Principal) ([]DeploymentMember, error) {
	if actor.Role != RoleOwner && actor.Role != RoleAdmin {
		return nil, ErrForbidden
	}
	records, err := s.repository.ListDeploymentMembers(ctx, actor.DeploymentID)
	if err != nil {
		return nil, err
	}
	members := make([]DeploymentMember, 0, len(records))
	for _, record := range records {
		members = append(members, memberFromRecord(record))
	}
	return members, nil
}

// CreateDeploymentMember 创建密码账号并加入当前 Deployment。
func (s *Service) CreateDeploymentMember(ctx context.Context, actor Principal, input CreateMemberInput) (*DeploymentMember, error) {
	if actor.Role != RoleOwner && actor.Role != RoleAdmin {
		return nil, ErrForbidden
	}
	username, err := normalizeUsername(input.Username)
	if err != nil {
		return nil, errors.Join(ErrRequestInvalid, err)
	}
	if err = validatePassword(input.Password); err != nil {
		return nil, errors.Join(ErrRequestInvalid, err)
	}
	role, err := normalizeRole(input.Role)
	if err != nil || role == RoleOwner {
		return nil, errors.Join(ErrRequestInvalid, err)
	}
	if actor.Role == RoleAdmin && role != RoleMember {
		return nil, ErrForbidden
	}
	displayName := strings.TrimSpace(input.DisplayName)
	if displayName == "" {
		displayName = username
	}
	if len(displayName) > 128 {
		return nil, errors.Join(ErrRequestInvalid, errors.New("显示名称不能超过 128 个字符"))
	}
	passwordHash, err := hashPassword(input.Password)
	if err != nil {
		return nil, err
	}
	record, err := s.repository.CreateDeploymentMember(ctx, actor.UserID, store.NewMemberRecord{
		DeploymentID: actor.DeploymentID,
		UserID:       newID("user"),
		IdentityID:   newID("idn"),
		CredentialID: newID("cred"),
		Username:     username,
		DisplayName:  displayName,
		PasswordHash: passwordHash,
		Role:         role,
		CreatedAt:    s.now(),
	})
	if errors.Is(err, store.ErrUsernameConflict) {
		return nil, errors.Join(ErrConflict, errors.New("用户名已存在"))
	}
	if err != nil {
		return nil, err
	}
	member := memberFromRecord(*record)
	return &member, nil
}

// UpdateDeploymentMember 更新成员角色或状态。
func (s *Service) UpdateDeploymentMember(ctx context.Context, actor Principal, userID string, input UpdateMemberInput) (*DeploymentMember, error) {
	if actor.Role != RoleOwner && actor.Role != RoleAdmin {
		return nil, ErrForbidden
	}
	userID = strings.TrimSpace(userID)
	if userID == "" || (input.Role == nil && input.Status == nil && input.DisplayName == nil) {
		return nil, ErrRequestInvalid
	}
	target, err := s.repository.DeploymentMemberByID(ctx, actor.DeploymentID, userID)
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
	if target.Role == RoleOwner {
		return nil, ErrForbidden
	}
	nextRole, nextStatus := target.Role, target.MembershipStatus
	if input.Role != nil {
		nextRole, err = normalizeRole(*input.Role)
		if err != nil || nextRole == RoleOwner {
			return nil, ErrRequestInvalid
		}
	}
	if input.Status != nil {
		nextStatus = strings.TrimSpace(*input.Status)
		if nextStatus != MembershipActive && nextStatus != MembershipRevoked {
			return nil, errors.Join(ErrRequestInvalid, errors.New("status 仅支持 active 或 revoked"))
		}
	}
	if actor.Role == RoleAdmin && (target.Role != RoleMember || nextRole != RoleMember) {
		return nil, ErrForbidden
	}
	if actor.UserID == target.UserID && nextStatus == MembershipRevoked {
		return nil, errors.Join(ErrConflict, errors.New("不能停用当前登录账号"))
	}
	record, err := s.repository.UpdateDeploymentMember(
		ctx, actor.DeploymentID, userID, actor.UserID,
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
