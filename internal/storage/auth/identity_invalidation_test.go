package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nexus-research-lab/nexus-control/internal/config"
)

// 使用独立 schema，验证先分配的事件提交前，后续事务不能推进消费水位。
func TestPostgresIdentityCommitOrder(t *testing.T) {
	rawURL := os.Getenv("CONTROL_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("CONTROL_TEST_POSTGRES_URL 未设置")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	admin, err := sql.Open("pgx", rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "control_identity_" + strings.ToLower(rand.Text())
	if _, err = admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`) }()
	endpoint, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	query := endpoint.Query()
	query.Set("search_path", schema)
	endpoint.RawQuery = query.Encode()
	database, err := sql.Open("pgx", endpoint.String())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err = database.ExecContext(ctx, `CREATE TABLE control_state (singleton_id INTEGER PRIMARY KEY);
		INSERT INTO control_state VALUES (1);
		CREATE TABLE identity_invalidations (event_id BIGSERIAL PRIMARY KEY, deployment_id TEXT, user_id TEXT,
		session_id TEXT, reason TEXT, created_at TIMESTAMPTZ, organization_id TEXT DEFAULT '', membership_revoked BOOLEAN DEFAULT FALSE)`); err != nil {
		t.Fatal(err)
	}
	repository := NewRepository(config.Config{DatabaseDriver: "postgres"}, database)
	first, err := repository.beginIdentityWrite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback()
	if err = repository.appendIdentityInvalidation(ctx, first, "deployment", "first", "", "principal_changed", time.Now()); err != nil {
		t.Fatal(err)
	}
	var blocker int
	if err = first.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		second, writeErr := repository.beginIdentityWrite(ctx)
		if writeErr == nil {
			defer second.Rollback()
			writeErr = repository.appendIdentityInvalidation(ctx, second, "deployment", "second", "", "session_revoked", time.Now())
			if writeErr == nil {
				writeErr = second.Commit()
			}
		}
		done <- writeErr
	}()
	for {
		var blocked bool
		if err = database.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`, blocker).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case err = <-done:
			t.Fatalf("后一个事件越过未提交事务: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if cursor, readErr := repository.LatestIdentityInvalidationID(ctx); readErr != nil || cursor != 0 {
		t.Fatalf("未提交事件变成可见水位: %d, %v", cursor, readErr)
	}
	if err = first.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	events, err := repository.ListIdentityInvalidations(ctx, 0, 10)
	if err != nil || len(events) != 2 || events[0].UserID != "first" || events[1].UserID != "second" || events[0].EventID >= events[1].EventID {
		t.Fatalf("事件提交顺序不一致: %+v, %v", events, err)
	}
}
