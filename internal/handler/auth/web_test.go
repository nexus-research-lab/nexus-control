package auth

import (
	"bytes"
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

func TestWebSetupLoginAndMemberAdministration(t *testing.T) {
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
	service := authservice.NewService(cfg, database, signer)
	server := httptest.NewServer(NewHTTPServer(cfg, service, nil).Handler())
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	setup := doWebJSON(t, client, http.MethodPost, server.URL+"/auth/v1/setup", server.URL, map[string]any{
		"username": "admin", "display_name": "Admin", "password": "password-123",
		"deployment_name": "Nexus",
	}, cfg.SetupToken)
	defer setup.Body.Close()
	if setup.StatusCode != http.StatusOK {
		t.Fatalf("setup status = %d", setup.StatusCode)
	}
	setupCookies := setup.Cookies()
	if len(setupCookies) != 1 || setupCookies[0].Name != cfg.SessionCookieName {
		t.Fatalf("setup cookies = %+v", setupCookies)
	}
	setupSessionToken := setupCookies[0].Value
	var setupPayload struct {
		Data struct {
			Authenticated bool   `json:"authenticated"`
			UserID        string `json:"user_id"`
			Role          string `json:"role"`
			SetupEnabled  bool   `json:"setup_enabled"`
		} `json:"data"`
	}
	if err = json.NewDecoder(setup.Body).Decode(&setupPayload); err != nil {
		t.Fatal(err)
	}
	if !setupPayload.Data.Authenticated ||
		setupPayload.Data.Role != authservice.RoleOwner ||
		!setupPayload.Data.SetupEnabled {
		t.Fatalf("setup payload = %+v", setupPayload.Data)
	}

	invalidRole := doWebJSON(t, client, http.MethodPost, server.URL+"/auth/v1/members", server.URL, map[string]any{
		"username": "invalid", "password": "password-456", "role": "superuser",
	}, "")
	defer invalidRole.Body.Close()
	if invalidRole.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid role status = %d", invalidRole.StatusCode)
	}

	created := doWebJSON(t, client, http.MethodPost, server.URL+"/auth/v1/members", server.URL, map[string]any{
		"username": "member", "display_name": "Member", "password": "password-456", "role": "member",
	}, "")
	defer created.Body.Close()
	if created.StatusCode != http.StatusOK {
		t.Fatalf("create member status = %d", created.StatusCode)
	}
	var createdPayload struct {
		Data authservice.DeploymentMember `json:"data"`
	}
	if err = json.NewDecoder(created.Body).Decode(&createdPayload); err != nil {
		t.Fatal(err)
	}
	if createdPayload.Data.UserID == "" || createdPayload.Data.Role != authservice.RoleMember {
		t.Fatalf("created member = %+v", createdPayload.Data)
	}

	listed, err := client.Get(server.URL + "/auth/v1/members")
	if err != nil {
		t.Fatal(err)
	}
	defer listed.Body.Close()
	var listedPayload struct {
		Data []authservice.DeploymentMember `json:"data"`
	}
	if err = json.NewDecoder(listed.Body).Decode(&listedPayload); err != nil {
		t.Fatal(err)
	}
	if listed.StatusCode != http.StatusOK || len(listedPayload.Data) != 2 {
		t.Fatalf("members status = %d, data = %+v", listed.StatusCode, listedPayload.Data)
	}

	revoked := doWebJSON(t, client, http.MethodPatch, server.URL+"/auth/v1/members/"+createdPayload.Data.UserID, server.URL, map[string]any{
		"status": authservice.MembershipRevoked,
	}, "")
	defer revoked.Body.Close()
	if revoked.StatusCode != http.StatusOK {
		t.Fatalf("revoke member status = %d", revoked.StatusCode)
	}
	invalidationRequest, err := http.NewRequest(
		http.MethodGet,
		server.URL+"/api/control/v1/internal/identity-invalidations?after=0&limit=10",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	invalidationRequest.Header.Set("Authorization", "Bearer "+cfg.ServiceToken)
	invalidationResponse, err := client.Do(invalidationRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer invalidationResponse.Body.Close()
	var invalidationPayload struct {
		Data struct {
			Events []authservice.IdentityInvalidation `json:"events"`
		} `json:"data"`
	}
	if err = json.NewDecoder(invalidationResponse.Body).Decode(&invalidationPayload); err != nil {
		t.Fatal(err)
	}
	if invalidationResponse.StatusCode != http.StatusOK ||
		len(invalidationPayload.Data.Events) != 1 ||
		invalidationPayload.Data.Events[0].UserID != createdPayload.Data.UserID {
		t.Fatalf(
			"identity invalidations status = %d, data = %+v",
			invalidationResponse.StatusCode,
			invalidationPayload.Data.Events,
		)
	}

	memberLogin := doWebJSON(t, client, http.MethodPost, server.URL+"/auth/v1/login", server.URL, map[string]any{
		"username": "member", "password": "password-456",
	}, "")
	defer memberLogin.Body.Close()
	if memberLogin.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked member login status = %d", memberLogin.StatusCode)
	}

	crossOrigin := doWebJSON(t, client, http.MethodPost, server.URL+"/auth/v1/members", "https://evil.example", map[string]any{
		"username": "blocked", "password": "password-789", "role": "member",
	}, "")
	defer crossOrigin.Body.Close()
	if crossOrigin.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin mutation status = %d", crossOrigin.StatusCode)
	}

	profile := doWebJSON(t, client, http.MethodPatch, server.URL+"/auth/v1/profile", server.URL, map[string]any{
		"avatar": "nexus://avatar/admin",
	}, "")
	defer profile.Body.Close()
	if profile.StatusCode != http.StatusOK {
		t.Fatalf("profile status = %d", profile.StatusCode)
	}

	const settledRequestID = "password-settled-001"
	if effect := readPasswordEffect(t, client, server.URL, settledRequestID); effect != authservice.PasswordChangeUnknown {
		t.Fatalf("unknown password effect = %q", effect)
	}
	settled := doWebJSON(
		t,
		client,
		http.MethodPost,
		server.URL+"/auth/v1/profile/password/receipt/not-applied",
		server.URL,
		map[string]string{"request_id": settledRequestID},
		"",
	)
	defer settled.Body.Close()
	if settled.StatusCode != http.StatusOK ||
		readPasswordEffect(t, client, server.URL, settledRequestID) != authservice.PasswordChangeNotApplied {
		t.Fatalf("settled password status = %d", settled.StatusCode)
	}

	const rejectedRequestID = "password-rejected-001"
	forged := doWebJSON(t, client, http.MethodPost, server.URL+"/auth/v1/profile/password", server.URL, map[string]any{
		"user_id": "forged-user", "request_id": "password-forged-001",
		"current_password": "password-123", "new_password": "password-789",
	}, "")
	defer forged.Body.Close()
	if forged.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged password status = %d", forged.StatusCode)
	}
	rejected := doWebJSON(t, client, http.MethodPost, server.URL+"/auth/v1/profile/password", server.URL, map[string]any{
		"request_id": rejectedRequestID, "current_password": "wrong-password", "new_password": "password-789",
	}, "")
	defer rejected.Body.Close()
	if rejected.StatusCode != http.StatusUnprocessableEntity ||
		readPasswordEffect(t, client, server.URL, rejectedRequestID) != authservice.PasswordChangeNotApplied {
		t.Fatalf("rejected password status = %d", rejected.StatusCode)
	}

	const committedRequestID = "password-committed-001"
	changed := doWebJSON(t, client, http.MethodPost, server.URL+"/auth/v1/profile/password", server.URL, map[string]any{
		"request_id": committedRequestID, "current_password": "password-123", "new_password": "password-789",
	}, "")
	defer changed.Body.Close()
	if changed.StatusCode != http.StatusOK ||
		readPasswordEffect(t, client, server.URL, committedRequestID) != authservice.PasswordChangeCommitted {
		t.Fatalf("committed password status = %d", changed.StatusCode)
	}
	newLogin := doWebJSON(t, &http.Client{}, http.MethodPost, server.URL+"/auth/v1/login", server.URL, map[string]any{
		"username": "admin", "password": "password-789",
	}, "")
	defer newLogin.Body.Close()
	if newLogin.StatusCode != http.StatusOK {
		t.Fatalf("new password login status = %d", newLogin.StatusCode)
	}

	setupPrincipal, err := service.ResolveSession(ctx, setupSessionToken)
	if err != nil || setupPrincipal == nil {
		t.Fatalf("resolve setup session: principal = %+v, err = %v", setupPrincipal, err)
	}
	logout := doWebJSON(t, client, http.MethodPost, server.URL+"/auth/v1/logout", server.URL, map[string]any{}, "")
	defer logout.Body.Close()
	logoutCookies := logout.Cookies()
	if logout.StatusCode != http.StatusOK || len(logoutCookies) != 1 ||
		logoutCookies[0].Path != "/" || logoutCookies[0].MaxAge >= 0 {
		t.Fatalf("logout status = %d, cookies = %+v", logout.StatusCode, logoutCookies)
	}
	events, err := service.ListIdentityInvalidations(ctx, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 ||
		events[0].Reason != "profile_changed" || events[0].UserID != setupPayload.Data.UserID || events[0].SessionID != "" ||
		events[1].Reason != "session_revoked" || events[1].SessionID != setupPrincipal.SessionID {
		t.Fatalf("account invalidations = %+v", events)
	}
	removedInternal := doWebJSON(
		t,
		client,
		http.MethodPost,
		server.URL+"/api/control/v1/internal/login",
		server.URL,
		map[string]string{"username": "admin", "password": "password-789"},
		cfg.ServiceToken,
	)
	defer removedInternal.Body.Close()
	if removedInternal.StatusCode != http.StatusNotFound {
		t.Fatalf("removed internal login status = %d", removedInternal.StatusCode)
	}
}

func readPasswordEffect(
	t *testing.T,
	client *http.Client,
	serverURL string,
	requestID string,
) authservice.PasswordChangeOutcome {
	t.Helper()
	response, err := client.Get(serverURL + "/auth/v1/profile/password/receipt?request_id=" + requestID)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload struct {
		Data struct {
			Effect authservice.PasswordChangeOutcome `json:"effect"`
		} `json:"data"`
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("password receipt status = %d", response.StatusCode)
	}
	if err = json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return payload.Data.Effect
}

func doWebJSON(t *testing.T, client *http.Client, method, endpoint, origin string, body any, bearer string) *http.Response {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, endpoint, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", origin)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
