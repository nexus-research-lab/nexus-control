// Package config 加载 .env 并读取 Nexus Control 的进程配置。
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config 是 Control 的最小运行配置。
type Config struct {
	Address              string
	LogLevel             string
	LogFormat            string
	LogPath              string
	LogStdout            bool
	LogNoColor           bool
	LogFileEnabled       bool
	LogRotateDaily       bool
	LogMaxSizeMB         int
	LogMaxAgeDays        int
	LogMaxBackups        int
	LogCompress          bool
	DatabaseDriver       string
	DatabaseURL          string
	APIBase              string
	WebAuthBase          string
	ServiceToken         string
	ServiceTokenFile     string
	SetupToken           string
	SigningPrivateKey    string
	SigningKeyFile       string
	SigningPublicKeyFile string
	SessionTTL           time.Duration
	SessionCookieName    string
	CookieSecure         bool
	CookieSameSite       string
	PrincipalTTL         time.Duration
	PrincipalAudience    string
}

// Load 从环境变量读取配置。
func Load() Config {
	_ = LoadDotEnv()
	homeDir, _ := os.UserHomeDir()
	dataDir := env("CONTROL_DATA_DIR", filepath.Join(homeDir, ".nexus", "control"))
	debug := envBool("DEBUG", false)
	logLevel := strings.TrimSpace(os.Getenv("LOG_LEVEL"))
	if logLevel == "" {
		if debug {
			logLevel = "debug"
		} else {
			logLevel = "info"
		}
	}
	logFormat := strings.TrimSpace(os.Getenv("LOG_FORMAT"))
	if logFormat == "" {
		if debug {
			logFormat = "pretty"
		} else {
			logFormat = "json"
		}
	}
	return Config{
		Address:              env("CONTROL_ADDRESS", "0.0.0.0:8020"),
		LogLevel:             logLevel,
		LogFormat:            logFormat,
		LogPath:              env("LOG_PATH", filepath.Join(dataDir, "logs", "logger.log")),
		LogStdout:            envBool("LOG_STDOUT", true),
		LogNoColor:           envBool("LOG_NO_COLOR", false),
		LogFileEnabled:       envBool("LOG_FILE_ENABLED", true),
		LogRotateDaily:       envBool("LOG_ROTATE_DAILY", true),
		LogMaxSizeMB:         envAnyInt("LOG_MAX_SIZE_MB", 10),
		LogMaxAgeDays:        envAnyInt("LOG_MAX_AGE_DAYS", 7),
		LogMaxBackups:        envAnyInt("LOG_MAX_BACKUPS", 7),
		LogCompress:          envBool("LOG_COMPRESS", true),
		DatabaseDriver:       strings.ToLower(env("CONTROL_DATABASE_DRIVER", "sqlite")),
		DatabaseURL:          env("CONTROL_DATABASE_URL", filepath.Join(dataDir, "data", "control.db")),
		APIBase:              env("CONTROL_API_BASE", "/api/control/v1"),
		WebAuthBase:          env("CONTROL_WEB_AUTH_BASE", "/auth/v1"),
		ServiceToken:         strings.TrimSpace(os.Getenv("CONTROL_SERVICE_TOKEN")),
		ServiceTokenFile:     env("CONTROL_SERVICE_TOKEN_FILE", filepath.Join(dataDir, "control-service.token")),
		SetupToken:           strings.TrimSpace(os.Getenv("CONTROL_SETUP_TOKEN")),
		SigningPrivateKey:    strings.TrimSpace(os.Getenv("CONTROL_SIGNING_PRIVATE_KEY")),
		SigningKeyFile:       env("CONTROL_SIGNING_KEY_FILE", filepath.Join(dataDir, "control-signing.key")),
		SigningPublicKeyFile: env("CONTROL_SIGNING_PUBLIC_KEY_FILE", filepath.Join(dataDir, "control-signing.pub")),
		SessionTTL:           time.Duration(envInt("CONTROL_SESSION_TTL_HOURS", 24)) * time.Hour,
		SessionCookieName:    env("AUTH_SESSION_COOKIE_NAME", "nexus_session"),
		CookieSecure:         envBool("AUTH_COOKIE_SECURE", false),
		CookieSameSite:       strings.ToLower(env("AUTH_COOKIE_SAMESITE", "lax")),
		PrincipalTTL:         time.Duration(envInt("CONTROL_PRINCIPAL_TTL_SECONDS", 60)) * time.Second,
		PrincipalAudience:    env("CONTROL_PRINCIPAL_AUDIENCE", "nexus-runtime"),
	}
}

// PrepareServiceToken 加载或生成 Control 与 Nexus Server 共用的服务凭据文件。
func (c *Config) PrepareServiceToken() error {
	if strings.TrimSpace(c.ServiceToken) != "" {
		return nil
	}
	data, err := os.ReadFile(c.ServiceTokenFile)
	if err == nil {
		c.ServiceToken = strings.TrimSpace(string(data))
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	buffer := make([]byte, 32)
	if _, err = rand.Read(buffer); err != nil {
		return err
	}
	c.ServiceToken = hex.EncodeToString(buffer)
	if err = os.MkdirAll(filepath.Dir(c.ServiceTokenFile), 0o700); err != nil {
		return err
	}
	return os.WriteFile(c.ServiceTokenFile, []byte(c.ServiceToken+"\n"), 0o600)
}

// Validate 拒绝会削弱服务间边界的配置。
func (c Config) Validate() error {
	if err := c.validateDatabase(); err != nil {
		return err
	}
	if len(c.ServiceToken) < 32 {
		return errors.New("CONTROL_SERVICE_TOKEN 至少需要 32 个字符")
	}
	if c.SetupToken != "" && len(c.SetupToken) < 32 {
		return errors.New("CONTROL_SETUP_TOKEN 至少需要 32 个字符")
	}
	if !strings.HasPrefix(c.APIBase, "/") || !strings.HasPrefix(c.WebAuthBase, "/") {
		return errors.New("Control API 路径必须以 / 开头")
	}
	if strings.TrimSpace(c.SessionCookieName) == "" {
		return errors.New("AUTH_SESSION_COOKIE_NAME 不能为空")
	}
	switch c.CookieSameSite {
	case "lax", "strict":
	case "none":
		if !c.CookieSecure {
			return errors.New("SameSite=None 必须启用 AUTH_COOKIE_SECURE")
		}
	default:
		return errors.New("AUTH_COOKIE_SAMESITE 仅支持 lax、strict 或 none")
	}
	if c.SessionTTL <= 0 || c.PrincipalTTL <= 0 {
		return errors.New("Session 与 Principal TTL 必须大于 0")
	}
	if c.PrincipalTTL > 5*time.Minute {
		return errors.New("CONTROL_PRINCIPAL_TTL_SECONDS 不能超过 300")
	}
	if strings.TrimSpace(c.PrincipalAudience) == "" {
		return errors.New("CONTROL_PRINCIPAL_AUDIENCE 不能为空")
	}
	return nil
}

func (c Config) validateDatabase() error {
	driver := strings.ToLower(strings.TrimSpace(c.DatabaseDriver))
	databaseURL := strings.TrimSpace(c.DatabaseURL)
	if databaseURL == "" {
		return errors.New("CONTROL_DATABASE_URL 不能为空")
	}
	switch driver {
	case "sqlite", "sqlite3":
		if strings.HasPrefix(strings.ToLower(databaseURL), "postgres") {
			return errors.New("SQLite driver 不能使用 PostgreSQL URL")
		}
	case "postgres", "postgresql", "pg", "pgx":
		parsed, err := url.Parse(databaseURL)
		if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" {
			return errors.New("PostgreSQL 必须使用完整的 postgres:// 或 postgresql:// URL")
		}
	default:
		return errors.New("CONTROL_DATABASE_DRIVER 仅支持 sqlite 或 postgres")
	}
	return nil
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func envAnyInt(name string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil {
		return fallback
	}
	return value
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
