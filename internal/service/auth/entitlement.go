package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	store "github.com/nexus-research-lab/nexus-control/internal/storage/auth"
)

const (
	PlanFree           = "free"
	PlanStatusActive   = "active"
	PlanStatusArchived = "archived"
)

var planKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// SubscriptionOverview 返回当前 Deployment 的套餐目录与成员有效额度。
func (s *Service) SubscriptionOverview(
	ctx context.Context,
	actor Principal,
) (SubscriptionOverview, error) {
	if actor.Role != RoleOwner && actor.Role != RoleAdmin {
		return SubscriptionOverview{}, ErrForbidden
	}
	plans, err := s.repository.ListSubscriptionPlans(ctx, actor.DeploymentID)
	if err != nil {
		return SubscriptionOverview{}, err
	}
	accounts, err := s.repository.ListSubscriptionAccounts(ctx, actor.DeploymentID)
	if err != nil {
		return SubscriptionOverview{}, err
	}
	result := SubscriptionOverview{
		Plans:     make([]SubscriptionPlan, 0, len(plans)),
		Accounts:  make([]SubscriptionAccount, 0, len(accounts)),
		UpdatedAt: s.now(),
	}
	for _, plan := range plans {
		result.Plans = append(result.Plans, subscriptionPlanFromRecord(plan))
	}
	for _, account := range accounts {
		result.Accounts = append(result.Accounts, subscriptionAccountFromRecord(account))
	}
	return result, nil
}

// UpsertSubscriptionPlan 在 Control 事务内更新套餐并通知所有受影响成员。
func (s *Service) UpsertSubscriptionPlan(
	ctx context.Context,
	actor Principal,
	input UpsertSubscriptionPlanInput,
) (SubscriptionOverview, error) {
	if actor.Role != RoleOwner && actor.Role != RoleAdmin {
		return SubscriptionOverview{}, ErrForbidden
	}
	normalized, err := normalizeSubscriptionPlan(input)
	if err != nil {
		return SubscriptionOverview{}, errors.Join(ErrRequestInvalid, err)
	}
	if err = s.repository.UpsertSubscriptionPlan(ctx, store.SubscriptionPlanRecord{
		DeploymentID:      actor.DeploymentID,
		PlanKey:           normalized.PlanKey,
		DisplayName:       normalized.DisplayName,
		Status:            normalized.Status,
		MonthlyTokenLimit: normalized.MonthlyTokenLimit,
		Notes:             normalized.Notes,
		SortOrder:         normalized.SortOrder,
	}, s.now()); err != nil {
		return SubscriptionOverview{}, err
	}
	return s.SubscriptionOverview(ctx, actor)
}

// UpdateMemberEntitlement 把成员绑定到当前 Deployment 的有效套餐。
func (s *Service) UpdateMemberEntitlement(
	ctx context.Context,
	actor Principal,
	userID string,
	input UpdateMemberEntitlementInput,
) (SubscriptionOverview, error) {
	if actor.Role != RoleOwner && actor.Role != RoleAdmin {
		return SubscriptionOverview{}, ErrForbidden
	}
	userID = strings.TrimSpace(userID)
	planKey := strings.TrimSpace(input.PlanKey)
	if userID == "" || !planKeyPattern.MatchString(planKey) {
		return SubscriptionOverview{}, ErrRequestInvalid
	}
	err := s.repository.SetMemberEntitlement(ctx, actor.DeploymentID, userID, planKey, s.now())
	if errors.Is(err, store.ErrPlanNotFound) {
		return SubscriptionOverview{}, ErrPlanNotFound
	}
	if errors.Is(err, store.ErrNotFound) {
		return SubscriptionOverview{}, ErrNotFound
	}
	if err != nil {
		return SubscriptionOverview{}, err
	}
	return s.SubscriptionOverview(ctx, actor)
}

// EffectiveEntitlement 返回 Nexus 本地投影所需的最小有效额度。
func (s *Service) EffectiveEntitlement(
	ctx context.Context,
	deploymentID string,
	userID string,
) (Entitlement, error) {
	deploymentID = strings.TrimSpace(deploymentID)
	userID = strings.TrimSpace(userID)
	if deploymentID == "" || userID == "" {
		return Entitlement{}, ErrRequestInvalid
	}
	record, err := s.repository.EffectiveEntitlement(ctx, deploymentID, userID)
	if errors.Is(err, store.ErrNotFound) {
		return Entitlement{}, ErrNotFound
	}
	if err != nil {
		return Entitlement{}, err
	}
	return entitlementFromRecord(*record), nil
}

func (s *Service) attachEntitlement(ctx context.Context, principal *Principal) error {
	if principal == nil {
		return ErrRequestInvalid
	}
	entitlement, err := s.EffectiveEntitlement(ctx, principal.DeploymentID, principal.UserID)
	if err != nil {
		return err
	}
	principal.Entitlement = entitlement
	return nil
}

func normalizeSubscriptionPlan(input UpsertSubscriptionPlanInput) (UpsertSubscriptionPlanInput, error) {
	input.PlanKey = strings.TrimSpace(input.PlanKey)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Status = strings.TrimSpace(input.Status)
	input.Notes = strings.TrimSpace(input.Notes)
	if !planKeyPattern.MatchString(input.PlanKey) {
		return UpsertSubscriptionPlanInput{}, errors.New("plan_key 无效")
	}
	if input.DisplayName == "" || len(input.DisplayName) > 128 {
		return UpsertSubscriptionPlanInput{}, errors.New("display_name 无效")
	}
	if input.Status == "" {
		input.Status = PlanStatusActive
	}
	if input.Status != PlanStatusActive && input.Status != PlanStatusArchived {
		return UpsertSubscriptionPlanInput{}, errors.New("status 无效")
	}
	if input.PlanKey == PlanFree && input.Status != PlanStatusActive {
		return UpsertSubscriptionPlanInput{}, errors.New("free 套餐不能归档")
	}
	if input.MonthlyTokenLimit != nil && *input.MonthlyTokenLimit < 0 {
		return UpsertSubscriptionPlanInput{}, errors.New("monthly_token_limit 无效")
	}
	if len(input.Notes) > 4096 {
		return UpsertSubscriptionPlanInput{}, errors.New("notes 过长")
	}
	if input.SortOrder == 0 {
		input.SortOrder = 100
	}
	return input, nil
}

func entitlementFromRecord(record store.EntitlementRecord) Entitlement {
	return Entitlement{
		PlanKey:           record.PlanKey,
		PlanName:          record.PlanName,
		MonthlyTokenLimit: record.MonthlyTokenLimit,
		UpdatedAt:         record.UpdatedAt.UTC(),
	}
}

func subscriptionPlanFromRecord(record store.SubscriptionPlanRecord) SubscriptionPlan {
	return SubscriptionPlan{
		PlanKey:           record.PlanKey,
		DisplayName:       record.DisplayName,
		Status:            record.Status,
		MonthlyTokenLimit: record.MonthlyTokenLimit,
		Notes:             record.Notes,
		SortOrder:         record.SortOrder,
	}
}

func subscriptionAccountFromRecord(record store.SubscriptionAccountRecord) SubscriptionAccount {
	updatedAt := record.UpdatedAt
	if record.EntitlementUpdatedAt.After(updatedAt) {
		updatedAt = record.EntitlementUpdatedAt
	}
	return SubscriptionAccount{
		UserID:            record.UserID,
		Username:          record.Username,
		DisplayName:       record.DisplayName,
		Role:              record.Role,
		UserStatus:        record.MembershipStatus,
		PlanKey:           record.PlanKey,
		PlanName:          record.PlanName,
		MonthlyTokenLimit: record.MonthlyTokenLimit,
		Avatar:            record.Avatar,
		LastLoginAt:       record.LastLoginAt,
		CreatedAt:         record.CreatedAt.UTC(),
		UpdatedAt:         updatedAt.UTC(),
	}
}

func validateImportedSubscriptionPlan(input UpsertSubscriptionPlanInput) error {
	_, err := normalizeSubscriptionPlan(input)
	if err != nil {
		return fmt.Errorf("无效订阅套餐 %q: %w", input.PlanKey, err)
	}
	return nil
}
