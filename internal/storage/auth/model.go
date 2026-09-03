package auth

import (
	"errors"
	"time"
)

var (
	ErrAlreadySetup     = errors.New("Control owner 已初始化")
	ErrUsernameConflict = errors.New("用户名已存在")
	ErrNotFound         = errors.New("记录不存在")
	ErrPlanNotFound     = errors.New("套餐不存在或已归档")
	ErrLastOwner        = errors.New("部署必须保留至少一个 active owner")
	ErrStateConflict    = errors.New("记录已被其他请求修改")
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
	DeploymentID string
	UserID       string
	Username     string
	DisplayName  string
	Role         string
	Avatar       string
	AuthMethod   string
	SessionID    string
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

type IdentityInvalidationRecord struct {
	EventID      int64
	DeploymentID string
	UserID       string
	SessionID    string
	Reason       string
	CreatedAt    time.Time
}

type RevokedSessionRecord struct {
	DeploymentID string
	UserID       string
	SessionID    string
}

type OwnerRecord struct {
	DeploymentID   string
	DeploymentName string
	UserID         string
	IdentityID     string
	CredentialID   string
	Username       string
	DisplayName    string
	PasswordHash   string
	CreatedAt      time.Time
}

type NewMemberRecord struct {
	DeploymentID string
	UserID       string
	IdentityID   string
	CredentialID string
	Username     string
	DisplayName  string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
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
	User              UserRecord
	Role              string
	IdentityID        string
	CredentialID      string
	PasswordHash      string
	PasswordAlgorithm string
	PasswordUpdatedAt time.Time
	CredentialCreated time.Time
	CredentialUpdated time.Time
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
