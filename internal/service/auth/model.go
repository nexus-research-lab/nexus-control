package auth

import (
	"errors"
	"time"
)

const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"

	StatusActive      = "active"
	StatusDisabled    = "disabled"
	MembershipActive  = "active"
	MembershipRevoked = "revoked"
	AuthPassword      = "password"
)

var (
	ErrAlreadySetup       = errors.New("Control owner 已初始化")
	ErrInvalidCredentials = errors.New("用户名或密码错误")
	ErrCurrentPassword    = errors.New("当前密码不正确")
	ErrUnauthenticated    = errors.New("登录状态无效或已过期")
	ErrForbidden          = errors.New("没有权限执行此操作")
	ErrConflict           = errors.New("请求与当前状态冲突")
	ErrNotFound           = errors.New("用户不存在")
	ErrRequestInvalid     = errors.New("请求参数无效")
	ErrRequestNotApplied  = errors.New("password change not applied")
)

// User 是 Control 中唯一的真人账号主体。
type User struct {
	UserID      string     `json:"user_id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Status      string     `json:"status"`
	Avatar      string     `json:"avatar,omitempty"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// DeploymentMember 是账号资料与当前 Deployment membership 的联合读模型。
type DeploymentMember struct {
	DeploymentID     string     `json:"deployment_id"`
	UserID           string     `json:"user_id"`
	Username         string     `json:"username"`
	DisplayName      string     `json:"display_name"`
	Role             string     `json:"role"`
	MembershipStatus string     `json:"membership_status"`
	Avatar           string     `json:"avatar,omitempty"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type CreateMemberInput struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Role        string `json:"role"`
}

type UpdateMemberInput struct {
	Role   *string `json:"role"`
	Status *string `json:"status"`
}

// Principal 是 Control 签发给下游服务的短期身份事实。
type Principal struct {
	DeploymentID string `json:"deployment_id"`
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	DisplayName  string `json:"display_name,omitempty"`
	Role         string `json:"role"`
	Avatar       string `json:"avatar,omitempty"`
	AuthMethod   string `json:"auth_method"`
	SessionID    string `json:"session_id"`
}

// PrincipalClaims 是签名 token 的稳定 v1 claim。
type PrincipalClaims struct {
	Version      int    `json:"v"`
	Issuer       string `json:"iss"`
	Audience     string `json:"aud"`
	IssuedAt     int64  `json:"iat"`
	ExpiresAt    int64  `json:"exp"`
	DeploymentID string `json:"deployment_id"`
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	DisplayName  string `json:"display_name,omitempty"`
	Role         string `json:"role"`
	Avatar       string `json:"avatar,omitempty"`
	AuthMethod   string `json:"auth_method"`
	SessionID    string `json:"session_id"`
}

// State 描述 Control 是否完成首次设置。
type State struct {
	SetupRequired        bool `json:"setup_required"`
	SetupEnabled         bool `json:"setup_enabled"`
	AuthRequired         bool `json:"auth_required"`
	PasswordLoginEnabled bool `json:"password_login_enabled"`
}

// LoginResult 返回新 Session 与登录后的 Principal。
type LoginResult struct {
	SessionToken string    `json:"session_token,omitempty"`
	Principal    Principal `json:"principal"`
}

// IdentityInvalidation 通知 Nexus 丢弃指定 Control 身份的本地租约。
type IdentityInvalidation struct {
	EventID      int64     `json:"event_id"`
	DeploymentID string    `json:"deployment_id"`
	UserID       string    `json:"user_id"`
	SessionID    string    `json:"session_id,omitempty"`
	Reason       string    `json:"reason"`
	CreatedAt    time.Time `json:"created_at"`
}

type SetupOwnerInput struct {
	Username       string `json:"username"`
	DisplayName    string `json:"display_name"`
	Password       string `json:"password"`
	DeploymentName string `json:"deployment_name"`
}

type LoginInput struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	ClientIP  string `json:"client_ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type ChangePasswordInput struct {
	UserID          string `json:"user_id"`
	RequestID       string `json:"request_id"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type PasswordChangeOutcome string

const (
	PasswordChangeUnknown    PasswordChangeOutcome = "unknown"
	PasswordChangeCommitted  PasswordChangeOutcome = "committed"
	PasswordChangeNotApplied PasswordChangeOutcome = "not_applied"
)
