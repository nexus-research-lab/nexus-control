package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadDefaultsDataDirToNexusControlDirectory(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	for _, name := range []string{
		"CONTROL_DATA_DIR",
		"CONTROL_DATABASE_URL",
		"CONTROL_SERVICE_TOKEN_FILE",
		"CONTROL_SIGNING_KEY_FILE",
		"CONTROL_SIGNING_PUBLIC_KEY_FILE",
	} {
		t.Setenv(name, "")
	}

	dataDir := filepath.Join(homeDir, ".nexus", "control")
	config := Load()
	if config.DatabaseURL != filepath.Join(dataDir, "data", "control.db") ||
		config.ServiceTokenFile != filepath.Join(dataDir, "control-service.token") ||
		config.SigningKeyFile != filepath.Join(dataDir, "control-signing.key") ||
		config.SigningPublicKeyFile != filepath.Join(dataDir, "control-signing.pub") {
		t.Fatalf("Control 默认数据路径未落在 %q: %+v", dataDir, config)
	}
}

func TestLoadPostgresKeepsSecretsInDataDir(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("CONTROL_DATA_DIR", dataDir)
	t.Setenv("CONTROL_DATABASE_DRIVER", "postgres")
	t.Setenv("CONTROL_DATABASE_URL", "postgres://control:secret@db.example/nexus")
	t.Setenv("CONTROL_SERVICE_TOKEN_FILE", "")
	t.Setenv("CONTROL_SIGNING_KEY_FILE", "")
	t.Setenv("CONTROL_SIGNING_PUBLIC_KEY_FILE", "")
	config := Load()
	if config.ServiceTokenFile != filepath.Join(dataDir, "control-service.token") ||
		config.SigningKeyFile != filepath.Join(dataDir, "control-signing.key") ||
		config.SigningPublicKeyFile != filepath.Join(dataDir, "control-signing.pub") {
		t.Fatalf("secret paths = %q, %q, %q", config.ServiceTokenFile, config.SigningKeyFile, config.SigningPublicKeyFile)
	}
}

func TestValidateSetupTokenStrength(t *testing.T) {
	config := Config{
		DatabaseDriver:    "sqlite",
		DatabaseURL:       ":memory:",
		ServiceToken:      strings.Repeat("s", 32),
		SetupToken:        "short",
		APIBase:           "/api/control/v1",
		WebAuthBase:       "/auth/v1",
		SessionCookieName: "nexus_session",
		CookieSameSite:    "lax",
		SessionTTL:        time.Hour,
		PrincipalTTL:      time.Minute,
		PrincipalAudience: "nexus-runtime",
	}
	if err := config.Validate(); err == nil {
		t.Fatal("短 setup token 应被拒绝")
	}
	config.SetupToken = strings.Repeat("x", 32)
	if err := config.Validate(); err != nil {
		t.Fatalf("有效 setup token 被拒绝: %v", err)
	}
}

func TestValidateRejectsInsecureSameSiteNone(t *testing.T) {
	config := Config{
		DatabaseDriver:    "sqlite",
		DatabaseURL:       ":memory:",
		ServiceToken:      strings.Repeat("s", 32),
		APIBase:           "/api/control/v1",
		WebAuthBase:       "/auth/v1",
		SessionCookieName: "nexus_session",
		CookieSameSite:    "none",
		SessionTTL:        time.Hour,
		PrincipalTTL:      time.Minute,
		PrincipalAudience: "nexus-runtime",
	}
	if err := config.Validate(); err == nil {
		t.Fatal("SameSite=None 未启用 Secure 时应被拒绝")
	}
}

func TestValidatePostgresURL(t *testing.T) {
	config := Config{
		DatabaseDriver:    "postgres",
		DatabaseURL:       "postgres://control:secret@db.example/nexus",
		ServiceToken:      strings.Repeat("s", 32),
		APIBase:           "/api/control/v1",
		WebAuthBase:       "/auth/v1",
		SessionCookieName: "nexus_session",
		CookieSameSite:    "lax",
		SessionTTL:        time.Hour,
		PrincipalTTL:      time.Minute,
		PrincipalAudience: "nexus-runtime",
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("有效 PostgreSQL URL 被拒绝: %v", err)
	}
	config.DatabaseURL = "./control.db"
	if err := config.Validate(); err == nil {
		t.Fatal("PostgreSQL driver 应拒绝文件路径")
	}
}
