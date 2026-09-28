package auth

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestDeploymentUsersStayIndependentFromOrganizations(t *testing.T) {
	ctx := t.Context()
	_, s := newImportTestService(t, filepath.Join(t.TempDir(), "control.db"))
	owner, err := s.SetupOwner(ctx, SetupOwnerInput{Username: "owner", Password: "password-123"})
	if err != nil {
		t.Fatal(err)
	}
	create := func(actor Principal, name, role string) (*DeploymentMember, error) {
		return s.CreateDeploymentMember(ctx, actor, CreateMemberInput{Username: name, Password: "password-123", Role: role})
	}
	member, err := create(*owner, "independent", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	login, err := s.Login(ctx, LoginInput{Username: "independent", Password: "password-123"})
	if err != nil {
		t.Fatal(err)
	}
	if login.Principal.OrganizationID != "" || login.Principal.WebAccessDisabled {
		t.Fatalf("平台 owner 有组织也不能替新用户加入: %+v", login.Principal)
	}
	if err = s.MutateOrganization(ctx, login.Principal, "create", OrganizationInput{Name: "Independent"}); err != nil {
		t.Fatal(err)
	}
	organizationOwner, err := s.ResolveSession(ctx, login.SessionToken)
	if err != nil || organizationOwner == nil {
		t.Fatalf("组织身份: %v", err)
	}
	if _, err = create(*organizationOwner, "forbidden", RoleMember); !errors.Is(err, ErrForbidden) {
		t.Fatalf("组织 owner 不得创建平台用户: %v", err)
	}
	if _, err = s.ListDeploymentMembers(ctx, *organizationOwner); !errors.Is(err, ErrForbidden) {
		t.Fatalf("组织 owner 不得读取平台目录: %v", err)
	}
	adminRole := RoleAdmin
	if _, err = s.UpdateDeploymentMember(ctx, *owner, member.UserID, UpdateMemberInput{Role: &adminRole}); err != nil {
		t.Fatal(err)
	}
	admin, err := s.ResolveSession(ctx, login.SessionToken)
	if err != nil || admin == nil || admin.Role != RoleAdmin || admin.OrganizationID != organizationOwner.OrganizationID || admin.OrganizationRole != RoleOwner {
		t.Fatalf("平台角色变更不能改组织: %+v %v", admin, err)
	}
	if _, err = create(*admin, "admin-child", RoleAdmin); !errors.Is(err, ErrForbidden) {
		t.Fatalf("平台 admin 不得提升其他用户: %v", err)
	}
	if _, err = create(*admin, "member-child", RoleMember); err != nil {
		t.Fatal(err)
	}
	memberRole := RoleMember
	if _, err = s.UpdateDeploymentMember(ctx, *owner, member.UserID, UpdateMemberInput{Role: &memberRole}); err != nil {
		t.Fatal(err)
	}
	if _, err = create(*admin, "stale-admin", RoleMember); err == nil {
		t.Fatal("事务必须拒绝已撤权的管理员快照")
	}
	if err = s.MutateOrganization(ctx, *owner, "dissolve", OrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	ownerLogin, err := s.Login(ctx, LoginInput{Username: "owner", Password: "password-123"})
	if err != nil {
		t.Fatal(err)
	}
	if ownerLogin.Principal.OrganizationID != "" {
		t.Fatal("owner 应无组织")
	}
	if _, err = create(ownerLogin.Principal, "web-user", RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err = create(ownerLogin.Principal, "another-owner", RoleOwner); !errors.Is(err, ErrRequestInvalid) {
		t.Fatalf("不能创建新平台 owner: %v", err)
	}
	revoked := MembershipRevoked
	if _, err = s.UpdateDeploymentMember(ctx, ownerLogin.Principal, member.UserID, UpdateMemberInput{Status: &revoked}); err != nil {
		t.Fatal(err)
	}
	if p, err := s.ResolveSession(ctx, login.SessionToken); err != nil || p != nil {
		t.Fatalf("撤销平台访问应撤销登录: %+v %v", p, err)
	}
	active := MembershipActive
	if _, err = s.UpdateDeploymentMember(ctx, ownerLogin.Principal, member.UserID, UpdateMemberInput{Status: &active}); err != nil {
		t.Fatal(err)
	}
	if p, err := s.ResolveSession(ctx, login.SessionToken); err != nil || p != nil {
		t.Fatalf("恢复平台访问不能复活旧登录: %+v %v", p, err)
	}
	login, err = s.Login(ctx, LoginInput{Username: "independent", Password: "password-123"})
	if err != nil || login.Principal.OrganizationID != organizationOwner.OrganizationID {
		t.Fatalf("平台访问变更保留组织关系: %+v %v", login, err)
	}
}
