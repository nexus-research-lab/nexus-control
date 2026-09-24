package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestNodeGrantScopeReplayAndRevocation(t *testing.T) {
	db, service := newImportTestService(t, filepath.Join(t.TempDir(), "control.db"))
	ctx := context.Background()
	owner, err := service.SetupOwner(ctx, SetupOwnerInput{Username: "owner", Password: "password-123"})
	if err != nil {
		t.Fatal(err)
	}
	login, err := service.Login(ctx, LoginInput{Username: "owner", Password: "password-123"})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := service.PublishAgent(ctx, *owner, PublishAgentInput{SourceAgentID: "local", Name: "Agent"})
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	input := RegisterNodeInput{NodeID: "device", Name: "My device", Credential: base64.RawURLEncoding.EncodeToString(secret), AgentIDs: []string{agent.AgentID}}
	for range 2 {
		if _, err = service.RegisterNode(ctx, login.Principal, input); err != nil {
			t.Fatal(err)
		}
	}
	for _, field := range []string{"user", "organization", "deployment"} {
		actor := login.Principal
		switch field {
		case "user":
			actor.UserID = "other"
		case "organization":
			actor.OrganizationID = "other"
		case "deployment":
			actor.DeploymentID = "other"
		}
		if _, err = service.Node(ctx, actor, input.NodeID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-%s read: %v", field, err)
		}
	}
	issued, err := service.ExchangeNodeToken(ctx, input.Credential)
	if err != nil {
		t.Fatal(err)
	}
	claims := verifyTestPrincipal(t, service.signer, issued.Token)
	peer, err := service.PublishAgent(ctx, *owner, PublishAgentInput{SourceAgentID: "peer", Name: "Peer"})
	if err != nil {
		t.Fatal(err)
	}
	withDirectory, err := service.ExchangeNodeTokenWithDirectory(ctx, input.Credential, []string{peer.AgentID, "foreign-agent"})
	if err != nil || len(withDirectory.Directory) != 1 || withDirectory.Directory[0].AgentID != peer.AgentID {
		t.Fatalf("公开目录范围错误: %+v %v", withDirectory.Directory, err)
	}
	directoryClaims := verifyTestPrincipal(t, service.signer, withDirectory.Token)
	if len(directoryClaims.AgentIDs) != 1 || directoryClaims.AgentIDs[0] != agent.AgentID {
		t.Fatal("读取目录扩大了机器执行范围")
	}
	if claims.ExpiresAt-claims.IssuedAt != int64(nodeTokenTTL/time.Second) {
		t.Fatal("unexpected node token lifetime")
	}
	if claims.Audience != "nexus-relay-node" || claims.Role != "node" || claims.NodeID != input.NodeID || claims.SessionID != "node:device" || claims.ParentSessionID != login.Principal.SessionID || len(claims.AgentIDs) != 1 || claims.AgentIDs[0] != agent.AgentID {
		t.Fatalf("unbound grant: %+v", claims)
	}
	if _, _, err = service.ExchangePrincipal(ctx, login.SessionToken, "nexus-relay-node"); !errors.Is(err, ErrRequestInvalid) {
		t.Fatalf("browser minted Node: %v", err)
	}
	changed := input
	changed.NodeID = "new-id-same-credential"
	if _, err = service.RegisterNode(ctx, login.Principal, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("credential reuse: %v", err)
	}
	changed.NodeID = "device\n"
	if _, err = service.RegisterNode(ctx, login.Principal, changed); !errors.Is(err, ErrRequestInvalid) {
		t.Fatalf("invalid node identity: %v", err)
	}
	changed = input
	changed.Name = "Overwritten"
	if _, err = service.RegisterNode(ctx, login.Principal, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed replay: %v", err)
	}
	changed.NodeID, changed.AgentIDs = "other", []string{"foreign-agent"}
	if _, err = service.RegisterNode(ctx, login.Principal, changed); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign Agent: %v", err)
	}
	for range 2 {
		if err = service.RevokeNode(ctx, login.Principal, input.NodeID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = service.ExchangeNodeToken(ctx, input.Credential); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked grant: %v", err)
	}
	if _, err = service.RegisterNode(ctx, login.Principal, input); !errors.Is(err, ErrConflict) {
		t.Fatalf("revived grant: %v", err)
	}
	events, err := service.ListIdentityInvalidations(ctx, 0, 256)
	if err != nil || len(events) != 1 || events[0].SessionID != "node:device" {
		t.Fatalf("node revocation: %+v %v", events, err)
	}
	// 撤销先于注册到达时，终止记录必须阻止迟到注册；不能依赖 404 或浏览器原 Session。
	input.NodeID = "cancel-before-registration"
	input.Credential = base64.RawURLEncoding.EncodeToString([]byte("23456789012345678901234567890123"))
	if err = service.RevokeNode(ctx, login.Principal, input.NodeID); err != nil {
		t.Fatal(err)
	}
	if err = service.RevokeNode(ctx, login.Principal, input.NodeID); err != nil {
		t.Fatal(err)
	}
	tombstone, err := service.Node(ctx, login.Principal, input.NodeID)
	if err != nil || tombstone.RevokedAt == nil {
		t.Fatalf("missing cancellation: %+v %v", tombstone, err)
	}
	if _, err = service.RegisterNode(ctx, login.Principal, input); !errors.Is(err, ErrConflict) {
		t.Fatalf("late registration revived: %v", err)
	}
	input.NodeID, input.Credential = "second", base64.RawURLEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	if _, err = service.RegisterNode(ctx, login.Principal, input); err != nil {
		t.Fatal(err)
	}
	// 浏览器自然过期不能切断设备授权，也不能让旧 Cookie 重新访问真人 API。
	if _, err = db.Exec(`UPDATE sessions SET expires_at=? WHERE session_id=?`, service.now().UTC().Add(-time.Hour), login.Principal.SessionID); err != nil {
		t.Fatal(err)
	}
	if actor, err := service.ResolveSession(ctx, login.SessionToken); err != nil || actor != nil {
		t.Fatalf("expired browser session revived: %+v %v", actor, err)
	}
	renewedLogin, err := service.Login(ctx, LoginInput{Username: "owner", Password: "password-123"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.ExchangeNodeToken(ctx, input.Credential); err != nil {
		t.Fatalf("session cleanup broke device renewal: %v", err)
	}
	if err = service.Logout(ctx, login.SessionToken); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ExchangeNodeToken(ctx, input.Credential); err == nil {
		t.Fatal("logged-out parent still grants execution")
	}
	input.NodeID, input.Credential = "after-login", base64.RawURLEncoding.EncodeToString([]byte("34567890123456789012345678901234"))
	if _, err = service.RegisterNode(ctx, renewedLogin.Principal, input); err != nil {
		t.Fatal(err)
	}
	hash, _, err := service.repository.PasswordCredential(ctx, owner.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.repository.TryCommitPasswordChange(ctx, owner.UserID, "password-reset", hash, "changed", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ExchangeNodeToken(ctx, input.Credential); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("password change retained device: %v", err)
	}
}
