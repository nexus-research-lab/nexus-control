package auth

import (
	"errors"
	"time"
)

var (
	ErrAlreadySetup      = errors.New("Control owner 已初始化")
	ErrUsernameConflict  = errors.New("用户名已存在")
	ErrNotFound          = errors.New("记录不存在")
	ErrPlanNotFound      = errors.New("套餐不存在或已归档")
	ErrLastOwner         = errors.New("部署必须保留至少一个 active owner")
	ErrStateConflict     = errors.New("记录已被其他请求修改")
	ErrInvitationInvalid = errors.New("组织邀请无效或已失效")
)

type UserRecord struct {
	UserID      string
	Username    string
	DisplayName string
	Status      string
	Avatar      string
	LastLoginAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type PrincipalRecord struct {
	WebAccessDisabled bool
	OrganizationRole  string
	DeploymentID      string
	OrganizationID    string
	OrganizationName  string
	UserID            string
	Username          string
	DisplayName       string
	Role              string
	Avatar            string
	AuthMethod        string
	SessionID         string
}

type SubscriptionPlanRecord struct {
	DeploymentID      string
	PlanKey           string
	DisplayName       string
	Status            string
	MonthlyTokenLimit *int64
	Notes             string
	SortOrder         int
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type EntitlementRecord struct {
	DeploymentID      string
	UserID            string
	PlanKey           string
	PlanName          string
	MonthlyTokenLimit *int64
	UpdatedAt         time.Time
}

type SubscriptionAccountRecord struct {
	DeploymentID         string
	UserID               string
	Username             string
	DisplayName          string
	Role                 string
	MembershipStatus     string
	Avatar               string
	LastLoginAt          *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
	PlanKey              string
	PlanName             string
	MonthlyTokenLimit    *int64
	EntitlementUpdatedAt time.Time
}

type DeploymentMemberRecord struct {
	DeploymentID     string
	UserID           string
	Username         string
	DisplayName      string
	Role             string
	MembershipStatus string
	Avatar           string
	LastLoginAt      *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type AgentRecord struct {
	AgentID        string
	DeploymentID   string
	OrganizationID string
	OwnerUserID    string
	SourceAgentID  string
	Name           string
	Avatar         string
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type IdentityInvalidationRecord struct {
	OrganizationID    string
	MembershipRevoked bool
	EventID           int64
	DeploymentID      string
	UserID            string
	SessionID         string
	Reason            string
	CreatedAt         time.Time
}

type RevokedSessionRecord struct {
	DeploymentID string
	UserID       string
	SessionID    string
}

type OwnerRecord struct {
	DeploymentID     string
	DeploymentName   string
	OrganizationID   string
	OrganizationName string
	UserID           string
	IdentityID       string
	CredentialID     string
	Username         string
	DisplayName      string
	PasswordHash     string
	CreatedAt        time.Time
}

type NewMemberRecord struct {
	DeploymentID   string
	OrganizationID string
	UserID         string
	IdentityID     string
	CredentialID   string
	Username       string
	DisplayName    string
	PasswordHash   string
	Role           string
	CreatedAt      time.Time
}

type OrganizationInvitationRecord struct {
	InvitationID     string
	DeploymentID     string
	OrganizationID   string
	OrganizationName string
	TokenHash        string
	Role             string
	CreatedByUserID  string
	AcceptedByUserID string
	ExpiresAt        time.Time
	AcceptedAt       *time.Time
	RevokedAt        *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type AcceptOrganizationInvitationRecord struct {
	TokenHash    string
	UserID       string
	IdentityID   string
	CredentialID string
	Username     string
	DisplayName  string
	PasswordHash string
	AcceptedAt   time.Time
}

type SessionRecord struct {
	SessionID string
	TokenHash string
	Principal PrincipalRecord
	ExpiresAt time.Time
	ClientIP  string
	UserAgent string
	CreatedAt time.Time
}

type LoginRecord struct {
	Principal       PrincipalRecord
	PasswordHash    string
	UserStatus      string
	MembershipState string
}

type ImportedUserRecord struct {
	WebAccessDisabled bool
	User              UserRecord
	Role              string
	MembershipStatus  string
	MembershipCreated time.Time
	MembershipUpdated time.Time
	IdentityID        string
	IdentityCreated   time.Time
	IdentityUpdated   time.Time
	CredentialID      string
	PasswordHash      string
	PasswordAlgorithm string
	PasswordUpdatedAt time.Time
	CredentialCreated time.Time
	CredentialUpdated time.Time
}

type ImportedDeploymentRecord struct {
	Organizations           []ImportedOrganizationRecord
	OrganizationMemberships []ImportedOrganizationMembership
	Invitations             []OrganizationInvitationRecord
	Invalidations           []IdentityInvalidationRecord
	DeploymentID            string
	Name                    string
	Status                  string
	OrganizationID          string
	OrganizationName        string
	OrganizationStatus      string
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

type ImportedOrganizationRecord struct {
	ID, Name, Status     string
	CreatedAt, UpdatedAt time.Time
}

type ImportedOrganizationMembership struct {
	OrganizationID, UserID, Role, Status string
	CreatedAt, UpdatedAt                 time.Time
}

type ImportedEntitlementRecord struct {
	UserID    string
	PlanKey   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type PasswordAttempt int

const (
	PasswordAttemptCommitted PasswordAttempt = iota
	PasswordAttemptExisting
	PasswordAttemptCredentialChanged
)
