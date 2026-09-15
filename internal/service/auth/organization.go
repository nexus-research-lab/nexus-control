package auth

import (
	"context"
	"errors"
	"strings"

	store "github.com/nexus-research-lab/nexus-control/internal/storage/auth"
)

type OrganizationInput struct {
	Name         string `json:"name"`
	TargetUserID string `json:"target_user_id"`
}

// MutateOrganization 不把组织所有者映射为平台管理员。
func (s *Service) MutateOrganization(ctx context.Context, actor Principal, action string, input OrganizationInput) error {
	input.Name, input.TargetUserID = strings.TrimSpace(input.Name), strings.TrimSpace(input.TargetUserID)
	if (action == "create" || action == "rename") && (input.Name == "" || len(input.Name) > 128) {
		return ErrRequestInvalid
	}
	if action == "transfer" && (input.TargetUserID == "" || len(input.TargetUserID) > 128) {
		return ErrRequestInvalid
	}
	if action != "create" && action != "leave" && action != "transfer" && action != "rename" && action != "dissolve" {
		return ErrRequestInvalid
	}
	return organizationError(s.repository.MutateOrganization(ctx, store.OrganizationCommand{
		Actor: principalRecord(actor), Action: action, OrganizationID: newID("org"), Name: input.Name, TargetUserID: input.TargetUserID, Now: s.now(),
	}))
}

func (s *Service) JoinOrganization(ctx context.Context, actor Principal, token string) error {
	if len(token) != 64 {
		return ErrRequestInvalid
	}
	return organizationError(s.repository.MutateOrganization(ctx, store.OrganizationCommand{Actor: principalRecord(actor), Action: "join", TokenHash: hashToken(token), Now: s.now()}))
}

func organizationError(err error) error {
	if errors.Is(err, store.ErrStateConflict) || errors.Is(err, store.ErrLastOwner) {
		return errors.Join(ErrConflict, err)
	}
	if errors.Is(err, store.ErrInvitationInvalid) {
		return ErrInvitationInvalid
	}
	return err
}

// RegisterAccount 公开注册可关闭；组织邀请仍可独立注册新账号。
func (s *Service) RegisterAccount(ctx context.Context, input LoginInput) error {
	if !s.registrationEnabled {
		return ErrForbidden
	}
	username, err := normalizeUsername(input.Username)
	if err != nil {
		return ErrRequestInvalid
	}
	if err = validatePassword(input.Password); err != nil {
		return ErrRequestInvalid
	}
	password, err := hashPassword(input.Password)
	if err != nil {
		return err
	}
	err = s.repository.RegisterAccount(ctx, store.NewMemberRecord{UserID: newID("user"), IdentityID: newID("idn"), CredentialID: newID("cred"), Username: username, DisplayName: username, PasswordHash: password, CreatedAt: s.now()})
	if errors.Is(err, store.ErrUsernameConflict) {
		return ErrConflict
	}
	if errors.Is(err, store.ErrNotFound) {
		return ErrForbidden
	}
	return err
}
