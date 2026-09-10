package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	store "github.com/nexus-research-lab/nexus-control/internal/storage/auth"
)

const (
	defaultInvitationHours = 7 * 24
	maxInvitationHours     = 30 * 24
)

// CreateOrganizationInvitation 创建只显示一次明文 token 的组织邀请。
func (s *Service) CreateOrganizationInvitation(
	ctx context.Context,
	actor Principal,
	input CreateOrganizationInvitationInput,
) (*CreatedOrganizationInvitation, error) {
	if actor.Role != RoleOwner && actor.Role != RoleAdmin {
		return nil, ErrForbidden
	}
	role, err := normalizeRole(input.Role)
	if err != nil || role == RoleOwner {
		return nil, ErrRequestInvalid
	}
	if actor.Role == RoleAdmin && role != RoleMember {
		return nil, ErrForbidden
	}
	hours := input.ExpiresInHours
	if hours == 0 {
		hours = defaultInvitationHours
	}
	if hours < 1 || hours > maxInvitationHours {
		return nil, ErrRequestInvalid
	}
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	now := s.now()
	record, err := s.repository.CreateOrganizationInvitation(ctx, store.OrganizationInvitationRecord{
		InvitationID: newID("invite"), OrganizationID: actor.OrganizationID,
		OrganizationName: actor.OrganizationName, TokenHash: hashToken(token), Role: role,
		CreatedByUserID: actor.UserID, ExpiresAt: now.Add(time.Duration(hours) * time.Hour),
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return nil, err
	}
	return &CreatedOrganizationInvitation{OrganizationInvitation: invitationFromRecord(*record), Token: token}, nil
}

// ListOrganizationInvitations 返回当前组织最近的邀请审计记录。
func (s *Service) ListOrganizationInvitations(ctx context.Context, actor Principal) ([]OrganizationInvitation, error) {
	if actor.Role != RoleOwner && actor.Role != RoleAdmin {
		return nil, ErrForbidden
	}
	records, err := s.repository.ListOrganizationInvitations(ctx, actor.OrganizationID)
	if err != nil {
		return nil, err
	}
	result := make([]OrganizationInvitation, 0, len(records))
	for _, record := range records {
		result = append(result, invitationFromRecord(record))
	}
	return result, nil
}

// RevokeOrganizationInvitation 撤销尚未使用的邀请。
func (s *Service) RevokeOrganizationInvitation(ctx context.Context, actor Principal, invitationID string) error {
	if actor.Role != RoleOwner && actor.Role != RoleAdmin {
		return ErrForbidden
	}
	invitationID = strings.TrimSpace(invitationID)
	if invitationID == "" || len(invitationID) > 128 {
		return ErrRequestInvalid
	}
	if actor.Role == RoleAdmin {
		record, err := s.repository.OrganizationInvitationByID(ctx, actor.OrganizationID, invitationID)
		if errors.Is(err, store.ErrInvitationInvalid) {
			return ErrInvitationInvalid
		}
		if err != nil {
			return err
		}
		if record.Role != RoleMember {
			return ErrForbidden
		}
	}
	if err := s.repository.RevokeOrganizationInvitation(ctx, actor.OrganizationID, invitationID, s.now()); err != nil {
		if errors.Is(err, store.ErrInvitationInvalid) {
			return ErrInvitationInvalid
		}
		return err
	}
	return nil
}

// PreviewOrganizationInvitation 返回注册页需要的最小邀请信息。
func (s *Service) PreviewOrganizationInvitation(ctx context.Context, token string) (*OrganizationInvitationPreview, error) {
	record, err := s.activeInvitation(ctx, token)
	if err != nil {
		return nil, err
	}
	return &OrganizationInvitationPreview{
		OrganizationName: record.OrganizationName, Role: record.Role, ExpiresAt: record.ExpiresAt,
	}, nil
}

// AcceptOrganizationInvitation 创建账号并原子加入邀请所属组织。
func (s *Service) AcceptOrganizationInvitation(
	ctx context.Context,
	input AcceptOrganizationInvitationInput,
) (*DeploymentMember, error) {
	token := strings.TrimSpace(input.Token)
	if _, err := s.activeInvitation(ctx, token); err != nil {
		return nil, err
	}
	username, err := normalizeUsername(input.Username)
	if err != nil {
		return nil, errors.Join(ErrRequestInvalid, err)
	}
	if err = validatePassword(input.Password); err != nil {
		return nil, errors.Join(ErrRequestInvalid, err)
	}
	displayName := strings.TrimSpace(input.DisplayName)
	if displayName == "" {
		displayName = username
	}
	if len(displayName) > 128 {
		return nil, ErrRequestInvalid
	}
	passwordHash, err := hashPassword(input.Password)
	if err != nil {
		return nil, err
	}
	record, err := s.repository.AcceptOrganizationInvitation(ctx, store.AcceptOrganizationInvitationRecord{
		TokenHash: hashToken(token), UserID: newID("user"), IdentityID: newID("idn"),
		CredentialID: newID("cred"), Username: username, DisplayName: displayName,
		PasswordHash: passwordHash, AcceptedAt: s.now(),
	})
	if errors.Is(err, store.ErrUsernameConflict) {
		return nil, ErrConflict
	}
	if errors.Is(err, store.ErrInvitationInvalid) {
		return nil, ErrInvitationInvalid
	}
	if err != nil {
		return nil, err
	}
	member := memberFromRecord(*record)
	return &member, nil
}

func (s *Service) activeInvitation(ctx context.Context, token string) (*store.OrganizationInvitationRecord, error) {
	if len(token) != 64 {
		return nil, ErrInvitationInvalid
	}
	record, err := s.repository.OrganizationInvitationByToken(ctx, hashToken(token))
	if errors.Is(err, store.ErrInvitationInvalid) {
		return nil, ErrInvitationInvalid
	}
	if err != nil {
		return nil, err
	}
	if record.AcceptedAt != nil || record.RevokedAt != nil || !record.ExpiresAt.After(s.now()) {
		return nil, ErrInvitationInvalid
	}
	return record, nil
}

func invitationFromRecord(record store.OrganizationInvitationRecord) OrganizationInvitation {
	return OrganizationInvitation{
		InvitationID: record.InvitationID, OrganizationID: record.OrganizationID,
		OrganizationName: record.OrganizationName, Role: record.Role,
		CreatedByUserID: record.CreatedByUserID, AcceptedByUserID: record.AcceptedByUserID,
		ExpiresAt: record.ExpiresAt, AcceptedAt: record.AcceptedAt, RevokedAt: record.RevokedAt,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
}
