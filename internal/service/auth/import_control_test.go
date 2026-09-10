package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nexus-research-lab/nexus-control/internal/storage"
)

func TestImportControlSQLitePreservesAuthority(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "source.db")
	sourceDatabase, sourceService := newImportTestService(t, sourcePath)
	owner, err := sourceService.SetupOwner(ctx, SetupOwnerInput{
		Username:       "admin",
		DisplayName:    "Admin",
		Password:       "password-123",
		DeploymentName: "Production",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sourceService.UpdateAvatar(ctx, owner.UserID, "avatar-owner"); err != nil {
		t.Fatal(err)
	}
	if _, err = sourceService.Login(ctx, LoginInput{Username: "admin", Password: "password-123"}); err != nil {
		t.Fatal(err)
	}
	member, err := sourceService.CreateMember(ctx, *owner, CreateMemberInput{
		Username: "member", DisplayName: "Member", Password: "password-456", Role: RoleAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	limit := int64(8192)
	if _, err = sourceService.UpsertSubscriptionPlan(ctx, *owner, UpsertSubscriptionPlanInput{
		PlanKey: "team", DisplayName: "Team", Status: PlanStatusActive,
		MonthlyTokenLimit: &limit, Notes: "团队套餐", SortOrder: 20,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = sourceService.UpdateMemberEntitlement(
		ctx,
		*owner,
		member.UserID,
		UpdateMemberEntitlementInput{PlanKey: "team"},
	); err != nil {
		t.Fatal(err)
	}
	revoked := MembershipRevoked
	if _, err = sourceService.UpdateMember(
		ctx,
		*owner,
		member.UserID,
		UpdateMemberInput{Status: &revoked},
	); err != nil {
		t.Fatal(err)
	}
	want := readAuthorityRows(t, sourceDatabase)
	if err = sourceDatabase.Close(); err != nil {
		t.Fatal(err)
	}

	targetPath := filepath.Join(tempDir, "target.db")
	targetDatabase, targetService := newImportTestService(t, targetPath)
	if err = targetService.ImportControlSQLite(ctx, sourcePath); err != nil {
		t.Fatal(err)
	}
	if got := readAuthorityRows(t, targetDatabase); !reflect.DeepEqual(got, want) {
		t.Fatalf("迁移后的账号权威不一致\ngot:  %#v\nwant: %#v", got, want)
	}
	var sessions, invalidations int
	if err = targetDatabase.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err = targetDatabase.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_invalidations`).Scan(&invalidations); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || invalidations != 0 {
		t.Fatalf("临时状态被迁移: sessions=%d invalidations=%d", sessions, invalidations)
	}
	login, err := targetService.Login(ctx, LoginInput{Username: "admin", Password: "password-123"})
	if err != nil {
		t.Fatal(err)
	}
	if login.Principal.DeploymentID != owner.DeploymentID || login.Principal.UserID != owner.UserID {
		t.Fatalf("迁移后身份 ID = %+v", login.Principal)
	}
	if _, err = targetService.Login(ctx, LoginInput{Username: "member", Password: "password-456"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("revoked member login err = %v", err)
	}
	if err = targetService.ImportControlSQLite(ctx, sourcePath); !errors.Is(err, ErrAlreadySetup) {
		t.Fatalf("重复导入 err = %v", err)
	}
}

func TestImportControlSQLiteRejectsAnyTargetData(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tempDir := t.TempDir()
	sourceDatabase, sourceService := newImportTestService(t, filepath.Join(tempDir, "source.db"))
	if _, err := sourceService.SetupOwner(ctx, SetupOwnerInput{
		Username: "admin", DisplayName: "Admin", Password: "password-123",
	}); err != nil {
		t.Fatal(err)
	}
	if err := sourceDatabase.Close(); err != nil {
		t.Fatal(err)
	}
	targetDatabase, targetService := newImportTestService(t, filepath.Join(tempDir, "target.db"))
	if _, err := targetDatabase.ExecContext(ctx, `
INSERT INTO identity_invalidations (deployment_id, user_id, reason, created_at)
VALUES ('dep_stale', 'user_stale', 'principal_changed', ?)`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := targetService.ImportControlSQLite(ctx, filepath.Join(tempDir, "source.db")); !errors.Is(err, ErrAlreadySetup) {
		t.Fatalf("非空目标导入 err = %v", err)
	}
	var deployments int
	if err := targetDatabase.QueryRowContext(ctx, `SELECT COUNT(*) FROM deployments`).Scan(&deployments); err != nil {
		t.Fatal(err)
	}
	if deployments != 0 {
		t.Fatalf("拒绝导入后 deployments = %d", deployments)
	}
}

func TestImportControlSQLiteRejectsUnknownSourceSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "source.db")
	sourceDatabase, sourceService := newImportTestService(t, sourcePath)
	if _, err := sourceService.SetupOwner(ctx, SetupOwnerInput{
		Username: "admin", DisplayName: "Admin", Password: "password-123",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := sourceDatabase.ExecContext(ctx, `
INSERT INTO goose_db_version (version_id, is_applied) VALUES (?, 1)`,
		controlSQLiteImportSchemaVersion+1,
	); err != nil {
		t.Fatal(err)
	}
	if err := sourceDatabase.Close(); err != nil {
		t.Fatal(err)
	}
	_, targetService := newImportTestService(t, filepath.Join(tempDir, "target.db"))
	err := targetService.ImportControlSQLite(ctx, sourcePath)
	if err == nil || !strings.Contains(err.Error(), "schema 版本") {
		t.Fatalf("未知源 schema 导入 err = %v", err)
	}
}

func newImportTestService(t *testing.T, path string) (*sql.DB, *Service) {
	t.Helper()
	cfg := testConfig("sqlite", path)
	database, err := storage.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	signer, err := LoadSigner("", filepath.Join(t.TempDir(), "signing.key"), "")
	if err != nil {
		t.Fatal(err)
	}
	return database, NewService(cfg, database, signer)
}

func readAuthorityRows(t *testing.T, database *sql.DB) map[string][][]string {
	t.Helper()
	queries := map[string]string{
		"deployments":  `SELECT deployment_id, name, status, created_at, updated_at FROM deployments ORDER BY deployment_id`,
		"organizations": `SELECT organization_id, deployment_id, name, status, created_at, updated_at FROM organizations ORDER BY organization_id`,
		"organization_memberships": `SELECT organization_id, user_id, role, status, created_at, updated_at FROM organization_memberships ORDER BY organization_id, user_id`,
		"users":        `SELECT user_id, username, display_name, status, avatar, last_login_at, created_at, updated_at FROM users ORDER BY user_id`,
		"identities":   `SELECT identity_id, user_id, provider, subject, created_at, updated_at FROM identities ORDER BY identity_id`,
		"credentials":  `SELECT credential_id, user_id, password_hash, password_algo, password_updated_at, created_at, updated_at FROM password_credentials ORDER BY credential_id`,
		"memberships":  `SELECT deployment_id, user_id, role, status, created_at, updated_at FROM deployment_memberships ORDER BY deployment_id, user_id`,
		"plans":        `SELECT deployment_id, plan_key, display_name, status, monthly_token_limit, notes, sort_order, created_at, updated_at FROM subscription_plans ORDER BY deployment_id, plan_key`,
		"entitlements": `SELECT deployment_id, user_id, plan_key, created_at, updated_at FROM member_entitlements ORDER BY deployment_id, user_id`,
	}
	result := make(map[string][][]string, len(queries))
	for name, query := range queries {
		rows, err := database.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(columns))
			targets := make([]any, len(values))
			for index := range values {
				targets[index] = &values[index]
			}
			if err = rows.Scan(targets...); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			row := make([]string, len(values))
			for index, value := range values {
				switch typed := value.(type) {
				case time.Time:
					row[index] = typed.UTC().Format(time.RFC3339Nano)
				case []byte:
					row[index] = string(typed)
				default:
					row[index] = fmt.Sprint(typed)
				}
			}
			result[name] = append(result[name], row)
		}
		if err = rows.Err(); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		if err = rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return result
}
