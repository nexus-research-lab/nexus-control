package auth

import (
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
)

// TestOrganizationLifecycle 验证账号独立、邀请加入、所有权移交和旧设备不可复活。
func TestOrganizationLifecycle(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	_, s := newImportTestService(t, filepath.Join(t.TempDir(), "control.db"))
	owner, err := s.SetupOwner(ctx, SetupOwnerInput{Username: "admin", Password: "password-123"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RegisterAccount(ctx, LoginInput{Username: "alice", Password: "password-123"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("默认禁止公开注册: %v", err)
	}
	s.registrationEnabled = true
	for _, name := range []string{"alice", "bob"} {
		if err = s.RegisterAccount(ctx, LoginInput{Username: name, Password: "password-123"}); err != nil {
			t.Fatal(err)
		}
	}
	alice, err := s.Login(ctx, LoginInput{Username: "alice", Password: "password-123"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.Login(ctx, LoginInput{Username: "bob", Password: "password-123"})
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(token string) Principal {
		t.Helper()
		p, e := s.ResolveSession(ctx, token)
		if e != nil || p == nil {
			t.Fatalf("账号 Session 丢失: %+v %v", p, e)
		}
		return *p
	}
	if alice.Principal.OrganizationID != "" || alice.Principal.Role != RoleMember {
		t.Fatalf("注册身份: %+v", alice.Principal)
	}
	if _, _, err = s.ExchangePrincipal(ctx, alice.SessionToken, relayUserAudience); !errors.Is(err, ErrForbidden) {
		t.Fatalf("无组织签发 Relay: %v", err)
	}
	if _, _, err = s.ExchangePrincipal(ctx, alice.SessionToken, "nexus-runtime"); err != nil {
		t.Fatal(err)
	}
	if err = s.MutateOrganization(ctx, alice.Principal, "create", OrganizationInput{Name: "Alice team"}); err != nil {
		t.Fatal(err)
	}
	a := resolve(alice.SessionToken)
	if a.Role != RoleMember || a.OrganizationRole != RoleOwner || a.OrganizationID == owner.OrganizationID {
		t.Fatalf("平台权限被提升: %+v", a)
	}
	if _, err = s.SubscriptionOverview(ctx, a); !errors.Is(err, ErrForbidden) {
		t.Fatalf("组织所有者取得平台管理权限: %v", err)
	}
	invite, err := s.CreateOrganizationInvitation(ctx, a, CreateOrganizationInvitationInput{Role: RoleMember})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.JoinOrganization(ctx, *owner, invite.Token); !errors.Is(err, ErrConflict) {
		t.Fatalf("已加入组织仍能加入另一个: %v", err)
	}
	if err = s.JoinOrganization(ctx, bob.Principal, invite.Token); err != nil {
		t.Fatal(err)
	}
	b := resolve(bob.SessionToken)
	if _, err = s.ListMembers(ctx, b); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateOrganizationInvitation(ctx, b, CreateOrganizationInvitationInput{Role: RoleMember}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("普通成员发邀请: %v", err)
	}
	agent, err := s.PublishAgent(ctx, b, PublishAgentInput{SourceAgentID: "local", Name: "Agent"})
	if err != nil {
		t.Fatal(err)
	}
	credential := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err = s.RegisterNode(ctx, b, RegisterNodeInput{NodeID: "device", Name: "Desktop", Credential: credential, AgentIDs: []string{agent.AgentID}}); err != nil {
		t.Fatal(err)
	}
	if err = s.MutateOrganization(ctx, a, "leave", OrganizationInput{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("所有者直接退出: %v", err)
	}
	if err = s.MutateOrganization(ctx, a, "transfer", OrganizationInput{TargetUserID: b.UserID}); err != nil {
		t.Fatal(err)
	}
	staleOwner := a
	a = resolve(alice.SessionToken)
	b = resolve(bob.SessionToken)
	if a.OrganizationRole != RoleAdmin || b.OrganizationRole != RoleOwner || b.Role != RoleMember {
		t.Fatalf("移交身份不正确: %+v %+v", a, b)
	}
	if _, err = s.CreateOrganizationInvitation(ctx, staleOwner, CreateOrganizationInvitationInput{Role: RoleAdmin}); err == nil {
		t.Fatal("旧所有者绕过事务授权")
	}
	if err = s.MutateOrganization(ctx, b, "transfer", OrganizationInput{TargetUserID: a.UserID}); err != nil {
		t.Fatal(err)
	}
	a = resolve(alice.SessionToken)
	b = resolve(bob.SessionToken)
	if err = s.MutateOrganization(ctx, b, "leave", OrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	b = resolve(bob.SessionToken)
	if b.OrganizationID != "" || b.OrganizationRole != "" || b.Role != RoleMember {
		t.Fatalf("退出状态: %+v", b)
	}
	invite, err = s.CreateOrganizationInvitation(ctx, a, CreateOrganizationInvitationInput{Role: RoleMember})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.JoinOrganization(ctx, b, invite.Token); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ExchangeNodeToken(ctx, credential); err == nil {
		t.Fatal("重新加入复活了旧设备")
	}
	if _, err = s.VerifyOwnedAgents(ctx, a.DeploymentID, a.OrganizationID, b.UserID, []string{agent.AgentID}); err == nil {
		t.Fatal("重新加入复活了旧 Agent 发布")
	}
	if err = s.MutateOrganization(ctx, a, "rename", OrganizationInput{Name: "Renamed"}); err != nil {
		t.Fatal(err)
	}
	if b = resolve(bob.SessionToken); b.OrganizationName != "Renamed" {
		t.Fatal("其他成员名称未更新")
	}
	if err = s.MutateOrganization(ctx, a, "dissolve", OrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	if resolve(alice.SessionToken).OrganizationID != "" || resolve(bob.SessionToken).OrganizationID != "" {
		t.Fatal("解散遗留组织权限")
	}
	if err = s.MutateOrganization(ctx, resolve(bob.SessionToken), "create", OrganizationInput{Name: "New"}); err != nil {
		t.Fatal(err)
	}
}
