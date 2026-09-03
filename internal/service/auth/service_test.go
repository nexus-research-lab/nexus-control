package auth

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nexus-research-lab/nexus-control/internal/config"
	"github.com/nexus-research-lab/nexus-control/internal/storage"
	_ "modernc.org/sqlite"
)

func TestSQLiteControlConformance(t *testing.T) {
	t.Parallel()
	cfg := testConfig("sqlite", filepath.Join(t.TempDir(), "control.db"))
	runControlConformance(t, cfg)
}

func TestPostgresControlConformance(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("CONTROL_TEST_POSTGRES_URL"))
	if databaseURL == "" {
		t.Skip("CONTROL_TEST_POSTGRES_URL 未设置")
	}
	runControlConformance(t, testConfig("postgres", databaseURL))
}

func runControlConformance(t *testing.T, cfg config.Config) {
	t.Helper()
	ctx := context.Background()
	database, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	signer, err := LoadSigner("", filepath.Join(t.TempDir(), "signing.key"), "")
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(cfg, database, signer)
	if state, stateErr := service.State(ctx); stateErr != nil || !state.SetupRequired || !state.AuthRequired || state.SetupEnabled {
		t.Fatalf("测试数据库必须为空，initial state = %+v, err = %v", state, stateErr)
	}
	owner, err := service.SetupOwner(ctx, SetupOwnerInput{Username: "admin", DisplayName: "Admin", Password: "password-123"})
	if err != nil {
		t.Fatal(err)
	}
	if owner.Role != RoleOwner || owner.DeploymentID == "" || owner.UserID == "" {
		t.Fatalf("owner = %+v", owner)
	}
	if _, err = service.Login(ctx, LoginInput{Username: "admin", Password: "wrong-password"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password err = %v", err)
	}
	login, err := service.Login(ctx, LoginInput{Username: "admin", Password: "password-123"})
	if err != nil {
		t.Fatal(err)
	}
	token, principal, err := service.ExchangePrincipal(ctx, login.SessionToken, "nexus-runtime")
	if err != nil {
		t.Fatal(err)
	}
	claims := verifyTestPrincipal(t, signer, token)
	if principal.UserID != owner.UserID || claims.UserID != owner.UserID || claims.Audience != "nexus-runtime" {
		t.Fatalf("principal = %+v, claims = %+v", principal, claims)
	}
	member, err := service.CreateMember(ctx, *owner, CreateMemberInput{
		Username: "member", Password: "password-456", Role: RoleMember,
	})
	if err != nil || member.UserID == "" {
		t.Fatalf("member = %+v, err = %v", member, err)
	}
	nextRole := RoleAdmin
	member, err = service.UpdateMember(ctx, *owner, member.UserID, UpdateMemberInput{Role: &nextRole})
	if err != nil || member.Role != RoleAdmin {
		t.Fatalf("updated member = %+v, err = %v", member, err)
	}
	events, err := service.ListIdentityInvalidations(ctx, 0, 10)
	if err != nil || len(events) != 1 || events[0].UserID != member.UserID || events[0].Reason != "principal_changed" {
		t.Fatalf("identity invalidations = %+v, err = %v", events, err)
	}
	if cursor, cursorErr := service.LatestIdentityInvalidationID(ctx); cursorErr != nil || cursor != events[0].EventID {
		t.Fatalf("identity invalidation cursor = %d, err = %v", cursor, cursorErr)
	}
	change := ChangePasswordInput{
		UserID: owner.UserID, RequestID: "password:test-1",
		CurrentPassword: "password-123", NewPassword: "password-789",
	}
	if _, err = service.ChangePassword(ctx, change); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ChangePassword(ctx, change); err != nil {
		t.Fatalf("committed password request replay: %v", err)
	}
	if outcome, outcomeErr := service.PasswordChangeOutcome(ctx, owner.UserID, change.RequestID); outcomeErr != nil || outcome != PasswordChangeCommitted {
		t.Fatalf("password outcome = %q, err = %v", outcome, outcomeErr)
	}
	if _, err = service.Login(ctx, LoginInput{Username: "admin", Password: "password-789"}); err != nil {
		t.Fatal(err)
	}
	if err = service.Logout(ctx, login.SessionToken); err != nil {
		t.Fatal(err)
	}
	if resolved, resolveErr := service.ResolveSession(ctx, login.SessionToken); resolveErr != nil || resolved != nil {
		t.Fatalf("resolved after logout = %+v, err = %v", resolved, resolveErr)
	}
}

func TestImportNexusSQLitePreservesUserAndPassword(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "nexus.db")
	source, err := sql.Open("sqlite", sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	passwordHash, err := hashPassword("password-123")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, statement := range []string{
		`CREATE TABLE users (user_id TEXT PRIMARY KEY, username TEXT NOT NULL, display_name TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL, avatar TEXT, last_login_at DATETIME, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)`,
		`CREATE TABLE auth_password_credentials (credential_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, password_hash TEXT NOT NULL, password_algo TEXT NOT NULL, password_updated_at DATETIME NOT NULL, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)`,
	} {
		if _, err = source.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = source.ExecContext(ctx, `INSERT INTO users VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?)`, "user_existing", "admin", "Admin", RoleOwner, StatusActive, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err = source.ExecContext(ctx, `INSERT INTO auth_password_credentials VALUES (?, ?, ?, 'argon2id', ?, ?, ?)`, "cred_existing", "user_existing", passwordHash, now, now, now); err != nil {
		t.Fatal(err)
	}
	if err = source.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig("sqlite", filepath.Join(tempDir, "control.db"))
	database, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	signer, err := LoadSigner("", filepath.Join(tempDir, "signing.key"), "")
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(cfg, database, signer)
	if err = service.ImportNexusSQLite(ctx, sourcePath, "Nexus"); err != nil {
		t.Fatal(err)
	}
	login, err := service.Login(ctx, LoginInput{Username: "admin", Password: "password-123"})
	if err != nil {
		t.Fatal(err)
	}
	if login.Principal.UserID != "user_existing" || login.Principal.Role != RoleOwner {
		t.Fatalf("imported principal = %+v", login.Principal)
	}
}

func testConfig(driver, databaseURL string) config.Config {
	return config.Config{
		DatabaseDriver: driver, DatabaseURL: databaseURL,
		SessionTTL: time.Hour, PrincipalTTL: time.Minute,
		PrincipalAudience: "nexus-runtime",
	}
}

func verifyTestPrincipal(t *testing.T, signer *Signer, token string) PrincipalClaims {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts = %d", len(parts))
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(signer.publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("Principal signature invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims PrincipalClaims
	if err = json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}
