// INPUT: Control 数据库驱动、连接 URL 与内嵌 migration。
// OUTPUT: 已配置连接池并完成当前方言迁移的 sql.DB。
// POS: Control 运行时和一次性导入命令共用的数据库入口。
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	controldb "github.com/nexus-research-lab/nexus-control/db"
	"github.com/nexus-research-lab/nexus-control/internal/config"
	"github.com/pressly/goose/v3"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

const postgresSchema = "control"

// Open 打开 Control 数据库并执行对应方言的内嵌迁移。
func Open(ctx context.Context, cfg config.Config) (*sql.DB, error) {
	driver := NormalizeSQLDriver(cfg.DatabaseDriver)
	dsn, err := normalizeDatabaseURL(driver, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if IsSQLiteSQLDriver(driver) {
		if err = ensureSQLiteParent(dsn); err != nil {
			return nil, err
		}
		if dsn, err = sqliteConnectionDSN(dsn); err != nil {
			return nil, err
		}
	}
	database, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	configurePool(database, driver)
	if err = database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, err
	}
	if IsSQLiteSQLDriver(driver) {
		var foreignKeys int
		if err = database.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			_ = database.Close()
			return nil, err
		}
		if foreignKeys != 1 {
			_ = database.Close()
			return nil, fmt.Errorf("sqlite foreign_keys = %d, want 1", foreignKeys)
		}
	} else if err = ensurePostgresSchema(ctx, database); err != nil {
		_ = database.Close()
		return nil, err
	}
	if err = migrate(ctx, database, driver); err != nil {
		_ = database.Close()
		return nil, err
	}
	return database, nil
}

func configurePool(database *sql.DB, driver string) {
	if IsSQLiteSQLDriver(driver) {
		database.SetMaxOpenConns(1)
		database.SetMaxIdleConns(1)
		return
	}
	database.SetMaxOpenConns(25)
	database.SetMaxIdleConns(5)
	database.SetConnMaxIdleTime(5 * time.Minute)
	database.SetConnMaxLifetime(30 * time.Minute)
}

func ensurePostgresSchema(ctx context.Context, database *sql.DB) error {
	var exists bool
	if err := database.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'control')`).Scan(&exists); err != nil {
		return fmt.Errorf("检查 PostgreSQL control schema: %w", err)
	}
	if exists {
		return nil
	}
	if _, err := database.ExecContext(ctx, `CREATE SCHEMA control`); err != nil {
		return fmt.Errorf("创建 PostgreSQL control schema: %w", err)
	}
	return nil
}

func migrate(ctx context.Context, database *sql.DB, driver string) error {
	migrations, err := fs.Sub(controldb.Migrations, "migrations/"+MigrationDirName(driver))
	if err != nil {
		return err
	}
	dialect := goose.DialectSQLite3
	if !IsSQLiteSQLDriver(driver) {
		dialect = goose.DialectPostgres
	}
	provider, err := goose.NewProvider(dialect, database, migrations)
	if err != nil {
		return err
	}
	_, err = provider.Up(ctx)
	return err
}

func normalizeDatabaseURL(driver, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if IsSQLiteSQLDriver(driver) {
		value = trimSQLiteScheme(value)
		return expandHomePath(value), nil
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" {
		return "", fmt.Errorf("CONTROL_DATABASE_URL 必须是完整的 PostgreSQL URL")
	}
	query := parsed.Query()
	query.Set("search_path", postgresSchema)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func trimSQLiteScheme(value string) string {
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "sqlite://") {
		return value[len("sqlite://"):]
	}
	return value
}

func expandHomePath(value string) string {
	if value == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, filepath.FromSlash(strings.TrimLeft(value[2:], `/\`)))
		}
	}
	return value
}

func ensureSQLiteParent(dsn string) error {
	path, _, _ := strings.Cut(dsn, "?")
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil
	}
	parent := filepath.Dir(path)
	if parent == "." || parent == "/" {
		return nil
	}
	return os.MkdirAll(parent, 0o700)
}

func sqliteConnectionDSN(dsn string) (string, error) {
	base, rawQuery, _ := strings.Cut(dsn, "?")
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", fmt.Errorf("解析 SQLite DSN: %w", err)
	}
	pragmas := values["_pragma"][:0]
	for _, pragma := range values["_pragma"] {
		name := strings.ToLower(strings.TrimSpace(pragma))
		if index := strings.IndexAny(name, "(= \t"); index >= 0 {
			name = name[:index]
		}
		if name != "busy_timeout" && name != "foreign_keys" {
			pragmas = append(pragmas, pragma)
		}
	}
	values.Set("_txlock", "immediate")
	values["_pragma"] = append(pragmas, "busy_timeout(5000)", "foreign_keys(1)")
	return base + "?" + values.Encode(), nil
}
