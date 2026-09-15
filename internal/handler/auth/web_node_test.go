package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nexus-research-lab/nexus-control/internal/config"
	authservice "github.com/nexus-research-lab/nexus-control/internal/service/auth"
	"github.com/nexus-research-lab/nexus-control/internal/storage"
)

func TestNodeHTTPRejectsCookieExchangeAndCrossOriginGrant(t *testing.T) {
	cfg := config.Config{DatabaseDriver: "sqlite", DatabaseURL: filepath.Join(t.TempDir(), "control.db"),
		APIBase: "/api/control/v1", WebAuthBase: "/auth/v1", ServiceToken: strings.Repeat("s", 32), SetupToken: strings.Repeat("x", 32),
		SessionTTL: time.Hour, SessionCookieName: "nexus_session", CookieSameSite: "lax", PrincipalTTL: time.Minute, PrincipalAudience: "nexus-runtime"}
	db, err := storage.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	signer, err := authservice.LoadSigner("", filepath.Join(t.TempDir(), "signing.key"), "")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewHTTPServer(cfg, authservice.NewService(cfg, db, signer), nil).Handler())
	defer server.Close()
	client := clientWithJar(t)
	setup := doWebJSON(t, client, http.MethodPost, server.URL+"/auth/v1/setup", server.URL,
		map[string]any{"username": "owner", "password": "password-123", "deployment_name": "Nexus"}, cfg.SetupToken)
	setup.Body.Close()
	if setup.StatusCode != 200 {
		t.Fatalf("setup: %d", setup.StatusCode)
	}
	published := doWebJSON(t, client, http.MethodPut, server.URL+"/auth/v1/agents/local", server.URL, map[string]any{"name": "Agent"}, "")
	var agent struct {
		Data authservice.Agent `json:"data"`
	}
	err = json.NewDecoder(published.Body).Decode(&agent)
	published.Body.Close()
	if err != nil || published.StatusCode != 200 || agent.Data.AgentID == "" {
		t.Fatalf("publish: %d %v", published.StatusCode, err)
	}
	credential := base64.RawURLEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	input := authservice.RegisterNodeInput{NodeID: "device", Name: "Device", Credential: credential, AgentIDs: []string{agent.Data.AgentID}}
	for _, origin := range []string{"https://other.example", server.URL} {
		response := doWebJSON(t, client, http.MethodPost, server.URL+"/auth/v1/nodes", origin, input, "")
		response.Body.Close()
		expected := http.StatusForbidden
		if origin == server.URL {
			expected = http.StatusOK
		}
		if response.StatusCode != expected {
			t.Fatalf("registration origin=%s status=%d", origin, response.StatusCode)
		}
	}
	// 精确查询不受最近 100 个设备列表窗口影响，且永不返回凭据。
	for _, id := range []string{"device", "missing"} {
		response := doWebJSON(t, client, http.MethodGet, server.URL+"/auth/v1/nodes/"+id, "", nil, "")
		var body map[string]any
		if err = json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		expected := http.StatusNotFound
		if id == "device" {
			expected = http.StatusOK
		}
		encoded, _ := json.Marshal(body)
		if response.StatusCode != expected || strings.Contains(string(encoded), credential) {
			t.Fatalf("node read %s: %d", id, response.StatusCode)
		}
	}
	// 即使带有效浏览器 Cookie，机器交换也不能用它替代节点凭据。
	for _, bearer := range []string{"", cfg.ServiceToken, credential} {
		response := doWebJSON(t, client, http.MethodPost, server.URL+"/auth/v1/nodes/token", "", nil, bearer)
		response.Body.Close()
		expected := http.StatusUnauthorized
		if bearer == credential {
			expected = http.StatusOK
		}
		if response.StatusCode != expected {
			t.Fatalf("machine exchange status=%d expected=%d", response.StatusCode, expected)
		}
	}
	response := doWebJSON(t, client, http.MethodDelete, server.URL+"/auth/v1/nodes/device", server.URL, nil, "")
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d", response.StatusCode)
	}
	response = doWebJSON(t, client, http.MethodPost, server.URL+"/auth/v1/nodes/token", "", nil, credential)
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked exchange: %d", response.StatusCode)
	}
}
