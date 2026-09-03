package auth

import (
	"context"
	"errors"
	"strings"

	store "github.com/nexus-research-lab/nexus-control/internal/storage/auth"
)

// ListMembers 返回当前 Deployment 的成员。
func (s *Service) ListMembers(ctx context.Context, actor Principal) ([]DeploymentMember, error) {
	if actor.Role != RoleOwner && actor.Role != RoleAdmin {
		return nil, ErrForbidden
	}
	records, err := s.repository.ListMembers(ctx, actor.DeploymentID)
	if err != nil {
		return nil, err
	}
	members := make([]DeploymentMember, 0, len(records))
	for _, record := range records {
		members = append(members, memberFromRecord(record))
	}
	return members, nil
}

// CreateMember 创建密码账号并加入当前 Deployment。
func (s *Service) CreateMember(ctx context.Context, actor Principal, input CreateMemberInput) (*DeploymentMember, error) {
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
	if err != nil {
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
	record, err := s.repository.CreateMember(ctx, store.NewMemberRecord{
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

// UpdateMember 更新成员角色或状态。
func (s *Service) UpdateMember(ctx context.Context, actor Principal, userID string, input UpdateMemberInput) (*DeploymentMember, error) {
	if actor.Role != RoleOwner && actor.Role != RoleAdmin {
		return nil, ErrForbidden
	}
	userID = strings.TrimSpace(userID)
	if userID == "" || (input.Role == nil && input.Status == nil) {
		return nil, ErrRequestInvalid
	}
	target, err := s.repository.MemberByID(ctx, actor.DeploymentID, userID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	nextRole, nextStatus := target.Role, target.MembershipStatus
	if input.Role != nil {
		nextRole, err = normalizeRole(*input.Role)
		if err != nil {
			return nil, errors.Join(ErrRequestInvalid, err)
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
	record, err := s.repository.UpdateMember(
		ctx, actor.DeploymentID, userID,
		target.Role, target.MembershipStatus,
		nextRole, nextStatus, s.now(),
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
		Avatar: record.Avatar, LastLoginAt: record.LastLoginAt,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
}
