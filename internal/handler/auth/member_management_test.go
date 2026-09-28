package auth

import (
	"bytes"
	"encoding/json"
	"github.com/nexus-research-lab/nexus-control/internal/config"
	authservice "github.com/nexus-research-lab/nexus-control/internal/service/auth"
	"github.com/nexus-research-lab/nexus-control/internal/storage"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagedMembersRequireLiveAdminAndRejectStaleUpdates(t *testing.T) {
	cfg := config.Config{DatabaseDriver: "sqlite", DatabaseURL: filepath.Join(t.TempDir(), "control.db"), APIBase: "/api/control/v1", WebAuthBase: "/auth/v1", ServiceToken: strings.Repeat("s", 32), SessionTTL: time.Hour, PrincipalTTL: time.Minute, PrincipalAudience: "nexus-runtime"}
	db, err := storage.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	signer, err := authservice.LoadSigner("", filepath.Join(t.TempDir(), "key"), "")
	if err != nil {
		t.Fatal(err)
	}
	service := authservice.NewService(cfg, db, signer)
	if _, err = service.SetupOwner(t.Context(), authservice.SetupOwnerInput{Username: "owner", Password: "test-password"}); err != nil {
		t.Fatal(err)
	}
	login, err := service.Login(t.Context(), authservice.LoginInput{Username: "owner", Password: "test-password"})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.MutateOrganization(t.Context(), login.Principal, "dissolve", authservice.OrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	login, err = service.Login(t.Context(), authservice.LoginInput{Username: "owner", Password: "test-password"})
	if err != nil || login.Principal.OrganizationID != "" {
		t.Fatalf("无组织 owner 登录失败: %v", err)
	}
	handler := NewHTTPServer(cfg, service, nil).Handler()
	call := func(actor authservice.Principal, operation, target string, version int64, input any, token string) (int, json.RawMessage) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"actor_user_id": actor.UserID, "session_id": actor.SessionID, "operation": operation, "target": target, "expected_version": version, "input": input})
		request := httptest.NewRequest(http.MethodPost, "/api/control/v1/internal/deployment-members/manage", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &envelope)
		return response.Code, envelope.Data
	}
	legacyRequest := httptest.NewRequest(http.MethodPost, "/api/control/v1/internal/members/manage", strings.NewReader(`{}`))
	legacyRequest.Header.Set("Authorization", "Bearer "+cfg.ServiceToken)
	legacyResponse := httptest.NewRecorder()
	handler.ServeHTTP(legacyResponse, legacyRequest)
	if legacyResponse.Code != http.StatusNotFound {
		t.Fatalf("旧组织成员端点不能接管部署用户操作: %d", legacyResponse.Code)
	}
	if code, _ := call(login.Principal, "list", "", 0, nil, ""); code != http.StatusUnauthorized {
		t.Fatalf("missing service credential: %d", code)
	}
	code, data := call(login.Principal, "create", "", 0, map[string]any{"username": "member", "password": "test-password", "role": "member"}, cfg.ServiceToken)
	if code != http.StatusOK {
		t.Fatalf("create: %d", code)
	}
	var member authservice.DeploymentMember
	_ = json.Unmarshal(data, &member)
	memberLogin, err := service.Login(t.Context(), authservice.LoginInput{Username: "member", Password: "test-password"})
	if err != nil {
		t.Fatal(err)
	}
	if memberLogin.Principal.OrganizationID != "" || memberLogin.Principal.WebAccessDisabled || memberLogin.Principal.Role != "member" {
		t.Fatalf("新建账号必须独立于组织且可访问 Web: %+v", memberLogin.Principal)
	}
	if code, _ = call(memberLogin.Principal, "list", "", 0, nil, cfg.ServiceToken); code != http.StatusForbidden {
		t.Fatalf("member read: %d", code)
	}
	_, data = call(login.Principal, "list", "", 0, nil, cfg.ServiceToken)
	var listed []authservice.DeploymentMember
	_ = json.Unmarshal(data, &listed)
	for _, entry := range listed {
		if entry.UserID == member.UserID {
			member = entry
		}
	}
	version := member.UpdatedAt.UnixMicro()
	code, data = call(login.Principal, "update", member.UserID, version, map[string]any{"display_name": "Updated", "role": "admin"}, cfg.ServiceToken)
	if code != http.StatusOK {
		t.Fatalf("update: %d", code)
	}
	_ = json.Unmarshal(data, &member)
	if member.DisplayName != "Updated" || member.Role != "admin" {
		t.Fatalf("update missing: %+v", member)
	}
	if code, _ = call(login.Principal, "remove", member.UserID, version, nil, cfg.ServiceToken); code != http.StatusConflict {
		t.Fatalf("stale update: %d", code)
	}
	if code, _ = call(memberLogin.Principal, "create", "", 0, map[string]any{"username": "elevated", "password": "test-password", "role": "admin"}, cfg.ServiceToken); code != http.StatusForbidden {
		t.Fatalf("admin escalation: %d", code)
	}
	if code, _ = call(login.Principal, "remove", member.UserID, member.UpdatedAt.UnixMicro(), nil, cfg.ServiceToken); code != http.StatusOK {
		t.Fatalf("remove: %d", code)
	}
	if principal, resolveErr := service.ResolveSession(t.Context(), memberLogin.SessionToken); resolveErr != nil || principal != nil {
		t.Fatal("撤销部署访问必须使原 Session 失效")
	}
	if err = service.Logout(t.Context(), login.SessionToken); err != nil {
		t.Fatal(err)
	}
	if code, _ = call(login.Principal, "list", "", 0, nil, cfg.ServiceToken); code == http.StatusOK {
		t.Fatal("logged out administrator retained authority")
	}
}
