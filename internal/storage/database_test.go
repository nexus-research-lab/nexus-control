package storage

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nexus-research-lab/nexus-control/internal/config"
)

func TestOpenSQLiteRunsControlMigration(t *testing.T) {
	t.Parallel()
	database, err := Open(context.Background(), config.Config{
		DatabaseDriver: "sqlite",
		DatabaseURL:    filepath.Join(t.TempDir(), "control.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	var singleton int
	if err = database.QueryRow(`SELECT singleton_id FROM control_state`).Scan(&singleton); err != nil || singleton != 1 {
		t.Fatalf("control_state = %d, err = %v", singleton, err)
	}
}

func TestPostgresURLAndDialectUseControlSchema(t *testing.T) {
	t.Parallel()
	dsn, err := normalizeDatabaseURL("postgres", "postgres://control:secret@db.example/nexus?sslmode=require&search_path=public")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dsn, "search_path=control") || strings.Contains(dsn, "search_path=public") {
		t.Fatalf("postgres dsn = %q", dsn)
	}
	dialect := NewSQLDialect("postgres")
	if dialect.Bind(2) != "$2" || dialect.ForUpdate() != " FOR UPDATE" {
		t.Fatalf("postgres dialect = bind %q, lock %q", dialect.Bind(2), dialect.ForUpdate())
	}
	if NewSQLDialect("sqlite").Bind(2) != "?" || NewSQLDialect("sqlite").ForUpdate() != "" {
		t.Fatal("sqlite dialect 不应生成 PostgreSQL 语法")
	}
}

func TestTrimSQLiteSchemePreservesAbsolutePath(t *testing.T) {
	t.Parallel()
	if path := trimSQLiteScheme("sqlite:///var/lib/nexus-control/control.db"); path != "/var/lib/nexus-control/control.db" {
		t.Fatalf("sqlite path = %q", path)
	}
}
