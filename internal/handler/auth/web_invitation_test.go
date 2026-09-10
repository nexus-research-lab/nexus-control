package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nexus-research-lab/nexus-control/internal/config"
	authservice "github.com/nexus-research-lab/nexus-control/internal/service/auth"
	"github.com/nexus-research-lab/nexus-control/internal/storage"
)

func TestOrganizationInvitationLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg := config.Config{
		DatabaseDriver: "sqlite", DatabaseURL: filepath.Join(t.TempDir(), "control.db"),
		APIBase: "/api/control/v1", WebAuthBase: "/auth/v1",
		ServiceToken: strings.Repeat("s", 32), SetupToken: strings.Repeat("x", 32),
		SessionTTL: time.Hour, SessionCookieName: "nexus_session", CookieSameSite: "lax",
		PrincipalTTL: time.Minute, PrincipalAudience: "nexus-runtime",
	}
	database, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	signer, err := authservice.LoadSigner("", filepath.Join(t.TempDir(), "signing.key"), "")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewHTTPServer(cfg, authservice.NewService(cfg, database, signer), nil).Handler())
	t.Cleanup(server.Close)
	owner := clientWithJar(t)
	setup := doWebJSON(t, owner, http.MethodPost, server.URL+"/auth/v1/setup", server.URL, map[string]any{
		"username": "owner", "password": "password-123", "deployment_name": "Nexus",
	}, cfg.SetupToken)
	setup.Body.Close()
	if setup.StatusCode != http.StatusOK {
		t.Fatalf("setup status = %d", setup.StatusCode)
	}

	created := doWebJSON(t, owner, http.MethodPost, server.URL+"/auth/v1/organization/invitations", server.URL, map[string]any{
		"role": "member", "expires_in_hours": 24,
	}, "")
	defer created.Body.Close()
	var createdPayload struct {
		Data authservice.CreatedOrganizationInvitation `json:"data"`
	}
	if err = json.NewDecoder(created.Body).Decode(&createdPayload); err != nil {
		t.Fatal(err)
	}
	if created.StatusCode != http.StatusOK || len(createdPayload.Data.Token) != 64 ||
		createdPayload.Data.JoinURL != server.URL+"/join/"+createdPayload.Data.Token {
		t.Fatalf("create status = %d, data = %+v", created.StatusCode, createdPayload.Data)
	}
	token := createdPayload.Data.Token
	preview, err := http.Get(server.URL + "/auth/v1/organization-invitations/" + token)
	if err != nil {
		t.Fatal(err)
	}
	preview.Body.Close()
	if preview.StatusCode != http.StatusOK {
		t.Fatalf("preview status = %d", preview.StatusCode)
	}

	member := clientWithJar(t)
	accepted := doWebJSON(t, member, http.MethodPost,
		server.URL+"/auth/v1/organization-invitations/"+token+"/accept", server.URL,
		map[string]any{"username": "member", "display_name": "Member", "password": "password-456"}, "")
	defer accepted.Body.Close()
	var acceptedPayload struct {
		Data struct {
			Authenticated  bool   `json:"authenticated"`
			OrganizationID string `json:"organization_id"`
		} `json:"data"`
	}
	if err = json.NewDecoder(accepted.Body).Decode(&acceptedPayload); err != nil {
		t.Fatal(err)
	}
	if accepted.StatusCode != http.StatusOK || !acceptedPayload.Data.Authenticated || acceptedPayload.Data.OrganizationID == "" {
		t.Fatalf("accept status = %d, data = %+v", accepted.StatusCode, acceptedPayload.Data)
	}
	reused := doWebJSON(t, clientWithJar(t), http.MethodPost,
		server.URL+"/auth/v1/organization-invitations/"+token+"/accept", server.URL,
		map[string]any{"username": "other", "password": "password-789"}, "")
	reused.Body.Close()
	if reused.StatusCode != http.StatusNotFound {
		t.Fatalf("reused invitation status = %d", reused.StatusCode)
	}

	listed, err := owner.Get(server.URL + "/auth/v1/organization/invitations")
	if err != nil {
		t.Fatal(err)
	}
	defer listed.Body.Close()
	var listedPayload struct {
		Data []authservice.OrganizationInvitation `json:"data"`
	}
	if err = json.NewDecoder(listed.Body).Decode(&listedPayload); err != nil {
		t.Fatal(err)
	}
	if len(listedPayload.Data) != 1 || listedPayload.Data[0].AcceptedByUserID == "" {
		t.Fatalf("invitations = %+v", listedPayload.Data)
	}
	revocable := doWebJSON(t, owner, http.MethodPost, server.URL+"/auth/v1/organization/invitations", server.URL, map[string]any{
		"role": "member",
	}, "")
	var revocablePayload struct {
		Data authservice.CreatedOrganizationInvitation `json:"data"`
	}
	if err = json.NewDecoder(revocable.Body).Decode(&revocablePayload); err != nil {
		t.Fatal(err)
	}
	revocable.Body.Close()
	revoked := doWebJSON(t, owner, http.MethodDelete,
		server.URL+"/auth/v1/organization/invitations/"+revocablePayload.Data.InvitationID,
		server.URL, nil, "")
	revoked.Body.Close()
	if revoked.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d", revoked.StatusCode)
	}
	revokedPreview, err := http.Get(server.URL + "/auth/v1/organization-invitations/" + revocablePayload.Data.Token)
	if err != nil {
		t.Fatal(err)
	}
	revokedPreview.Body.Close()
	if revokedPreview.StatusCode != http.StatusNotFound {
		t.Fatalf("revoked preview status = %d", revokedPreview.StatusCode)
	}
}

func clientWithJar(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}
