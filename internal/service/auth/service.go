package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/nexus-research-lab/nexus-control/internal/config"
	store "github.com/nexus-research-lab/nexus-control/internal/storage/auth"
)

// Service 持有 Control 的认证规则与 Principal 签发入口。
type Service struct {
	repository   *store.Repository
	signer       *Signer
	now          func() time.Time
	sessionTTL   time.Duration
	principalTTL time.Duration
	audience     string
	setupEnabled bool
}

// NewService 创建认证服务。
func NewService(cfg config.Config, database *sql.DB, signer *Signer) *Service {
	return &Service{
		repository:   store.NewRepository(cfg, database),
		signer:       signer,
		now:          func() time.Time { return time.Now().UTC() },
		sessionTTL:   cfg.SessionTTL,
		principalTTL: cfg.PrincipalTTL,
		audience:     strings.TrimSpace(cfg.PrincipalAudience),
		setupEnabled: strings.TrimSpace(cfg.SetupToken) != "",
	}
}

// Health 检查数据库连接。
func (s *Service) Health(ctx context.Context) error {
	return s.repository.Ping(ctx)
}

// State 返回 Control 首次设置状态。
func (s *Service) State(ctx context.Context) (State, error) {
	required, err := s.repository.SetupRequired(ctx)
	if err != nil {
		return State{}, err
	}
	return State{
		SetupRequired:        required,
		SetupEnabled:         s.setupEnabled,
		AuthRequired:         true,
		PasswordLoginEnabled: !required,
	}, nil
}

// SetupOwner 创建首个 Deployment 与 owner。
func (s *Service) SetupOwner(ctx context.Context, input SetupOwnerInput) (*Principal, error) {
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
		return nil, errors.Join(ErrRequestInvalid, errors.New("显示名称不能超过 128 个字符"))
	}
	deploymentName := strings.TrimSpace(input.DeploymentName)
	if deploymentName == "" {
		deploymentName = "Nexus"
	}
	if len(deploymentName) > 128 {
		return nil, errors.Join(ErrRequestInvalid, errors.New("Deployment 名称不能超过 128 个字符"))
	}
	passwordHash, err := hashPassword(input.Password)
	if err != nil {
		return nil, err
	}
	principal := Principal{
		DeploymentID: newID("dep"),
		UserID:       newID("user"),
		Username:     username,
		DisplayName:  displayName,
		Role:         RoleOwner,
		AuthMethod:   AuthPassword,
	}
	err = s.repository.CreateOwner(ctx, store.OwnerRecord{
		DeploymentID:   principal.DeploymentID,
		DeploymentName: deploymentName,
		UserID:         principal.UserID,
		IdentityID:     newID("idn"),
		CredentialID:   newID("cred"),
		Username:       username,
		DisplayName:    displayName,
		PasswordHash:   passwordHash,
		CreatedAt:      s.now(),
	})
	if errors.Is(err, store.ErrAlreadySetup) {
		return nil, ErrAlreadySetup
	}
	if err != nil {
		return nil, err
	}
	return &principal, nil
}

// Login 校验密码并创建 Session。
func (s *Service) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	username, err := normalizeUsername(input.Username)
	if err != nil || strings.TrimSpace(input.Password) == "" || len(input.Password) > maxPasswordLength {
		return nil, ErrInvalidCredentials
	}
	record, err := s.repository.LoginRecord(ctx, username)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, ErrInvalidCredentials
	}
	matched, err := verifyPassword(input.Password, record.PasswordHash)
	if err != nil || !matched || record.UserStatus != StatusActive || record.MembershipState != MembershipActive {
		return nil, ErrInvalidCredentials
	}
	principal := principalFromRecord(record.Principal)
	principal.AuthMethod = AuthPassword
	principal.SessionID = newID("sess")
	sessionToken, err := newToken()
	if err != nil {
		return nil, err
	}
	now := s.now()
	if err = s.repository.CreateSession(ctx, store.SessionRecord{
		SessionID: principal.SessionID,
		TokenHash: hashToken(sessionToken),
		Principal: principalRecord(principal),
		ExpiresAt: now.Add(s.sessionTTL),
		ClientIP:  input.ClientIP,
		UserAgent: input.UserAgent,
		CreatedAt: now,
	}); err != nil {
		return nil, err
	}
	return &LoginResult{SessionToken: sessionToken, Principal: principal}, nil
}

// Logout 撤销当前 Session。
func (s *Service) Logout(ctx context.Context, sessionToken string) error {
	if strings.TrimSpace(sessionToken) == "" {
		return nil
	}
	_, err := s.repository.RevokeSession(ctx, hashToken(sessionToken), s.now())
	return err
}

// ResolveSession 解析浏览器 Session；无凭据或已失效时返回 nil。
func (s *Service) ResolveSession(ctx context.Context, sessionToken string) (*Principal, error) {
	if strings.TrimSpace(sessionToken) == "" {
		return nil, nil
	}
	now := s.now()
	record, err := s.repository.ResolveSessionByTokenHash(ctx, hashToken(sessionToken), now)
	if err != nil || record == nil {
		return nil, err
	}
	if err = s.repository.TouchSession(ctx, record.SessionID, now); err != nil {
		return nil, err
	}
	principal := principalFromRecord(*record)
	return &principal, nil
}

// VerifyBoundHuman 校验下游请求绑定的人类账号与 Session。
func (s *Service) VerifyBoundHuman(ctx context.Context, userID, sessionID string) (*Principal, error) {
	now := s.now()
	record, err := s.repository.ResolveSessionByID(ctx, strings.TrimSpace(sessionID), now)
	if err != nil {
		return nil, err
	}
	if record == nil || record.UserID != strings.TrimSpace(userID) {
		return nil, ErrInvalidCredentials
	}
	if err = s.repository.TouchSession(ctx, record.SessionID, now); err != nil {
		return nil, err
	}
	principal := principalFromRecord(*record)
	return &principal, nil
}

// ExchangeBoundHuman 校验指定人类 Session 并签发短期身份票据。
func (s *Service) ExchangeBoundHuman(ctx context.Context, userID, sessionID, audience string) (string, error) {
	principal, err := s.VerifyBoundHuman(ctx, userID, sessionID)
	if err != nil {
		return "", err
	}
	return s.signPrincipal(*principal, audience)
}

// ExchangePrincipal 为 Nexus Runtime 签发短期身份票据。
func (s *Service) ExchangePrincipal(ctx context.Context, sessionToken, audience string) (string, *Principal, error) {
	principal, err := s.ResolveSession(ctx, sessionToken)
	if err != nil || principal == nil {
		return "", principal, err
	}
	token, err := s.signPrincipal(*principal, audience)
	return token, principal, err
}

func (s *Service) signPrincipal(principal Principal, audience string) (string, error) {
	audience = strings.TrimSpace(audience)
	if audience == "" || audience != s.audience {
		return "", errors.Join(ErrRequestInvalid, errors.New("Principal audience 无效"))
	}
	return s.signer.Sign(principal, audience, s.now(), s.principalTTL)
}

// ActiveRole 返回账号的当前 active 角色。
func (s *Service) ActiveRole(ctx context.Context, userID string) (string, error) {
	role, err := s.repository.ActiveRole(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrNotFound
	}
	return role, err
}

// UserByID 返回用户资料。
func (s *Service) UserByID(ctx context.Context, userID string) (*User, error) {
	record, err := s.repository.UserByID(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	user := userFromRecord(*record)
	return &user, nil
}

// UpdateAvatar 更新用户头像标识。
func (s *Service) UpdateAvatar(ctx context.Context, userID, avatar string) (*User, error) {
	avatar = strings.TrimSpace(avatar)
	if len(avatar) > 255 {
		return nil, errors.Join(ErrRequestInvalid, errors.New("头像标识不能超过 255 个字符"))
	}
	if err := s.repository.UpdateAvatar(ctx, userID, avatar, s.now()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return s.UserByID(ctx, userID)
}

// PublicKey 返回 Principal token 的 Ed25519 公钥。
func (s *Service) PublicKey() string { return s.signer.PublicKey() }

func principalFromRecord(record store.PrincipalRecord) Principal {
	return Principal{
		DeploymentID: record.DeploymentID,
		UserID:       record.UserID,
		Username:     record.Username,
		DisplayName:  record.DisplayName,
		Role:         record.Role,
		Avatar:       record.Avatar,
		AuthMethod:   record.AuthMethod,
		SessionID:    record.SessionID,
	}
}

func principalRecord(principal Principal) store.PrincipalRecord {
	return store.PrincipalRecord{
		DeploymentID: principal.DeploymentID,
		UserID:       principal.UserID,
		Username:     principal.Username,
		DisplayName:  principal.DisplayName,
		Role:         principal.Role,
		Avatar:       principal.Avatar,
		AuthMethod:   principal.AuthMethod,
		SessionID:    principal.SessionID,
	}
}

func userFromRecord(record store.UserRecord) User {
	return User{
		UserID: record.UserID, Username: record.Username, DisplayName: record.DisplayName,
		Status: record.Status, Avatar: record.Avatar, LastLoginAt: record.LastLoginAt,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
}
