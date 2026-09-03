package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	store "github.com/nexus-research-lab/nexus-control/internal/storage/auth"

	_ "modernc.org/sqlite"
)

// ImportNexusSQLite 从停止写入的 Nexus SQLite 复制账号和密码哈希。
// Session 故意不导入，切换后所有浏览器必须重新登录。
func (s *Service) ImportNexusSQLite(ctx context.Context, sourcePath, deploymentName string) error {
	state, err := s.State(ctx)
	if err != nil {
		return err
	}
	if !state.SetupRequired {
		return ErrAlreadySetup
	}
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return errors.New("源 Nexus SQLite 路径无效")
	}
	sourcePath, err = filepath.Abs(sourcePath)
	if err != nil {
		return errors.New("源 Nexus SQLite 路径无效")
	}
	sourceURL := (&url.URL{Scheme: "file", Path: sourcePath}).String() + "?mode=ro"
	source, err := sql.Open("sqlite", sourceURL)
	if err != nil {
		return err
	}
	defer source.Close()
	rows, err := source.QueryContext(ctx, `
SELECT u.user_id, u.username, u.display_name, u.role, u.status, u.avatar,
       u.last_login_at, u.created_at, u.updated_at,
       c.credential_id, c.password_hash, c.password_algo,
       c.password_updated_at, c.created_at, c.updated_at
FROM users u JOIN auth_password_credentials c ON c.user_id = u.user_id
WHERE u.user_id <> '__system__' ORDER BY u.created_at ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := make([]store.ImportedUserRecord, 0)
	for rows.Next() {
		item, scanErr := scanImportedUser(rows)
		if scanErr != nil {
			return scanErr
		}
		if _, err = normalizeRole(item.Role); err != nil || item.PasswordAlgorithm != "argon2id" {
			return fmt.Errorf("用户 %s 的角色或密码算法不受支持", item.User.UserID)
		}
		item.IdentityID = newID("idn")
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(items) == 0 {
		return errors.New("源 Nexus 没有可导入的密码用户")
	}
	deploymentName = strings.TrimSpace(deploymentName)
	if deploymentName == "" {
		deploymentName = "Nexus"
	}
	err = s.repository.ImportDeployment(ctx, newID("dep"), deploymentName, items, s.now())
	if errors.Is(err, store.ErrAlreadySetup) {
		return ErrAlreadySetup
	}
	return err
}

func scanImportedUser(row interface{ Scan(...any) error }) (store.ImportedUserRecord, error) {
	var item store.ImportedUserRecord
	var avatar sql.NullString
	var lastLogin sql.NullTime
	err := row.Scan(
		&item.User.UserID, &item.User.Username, &item.User.DisplayName, &item.Role,
		&item.User.Status, &avatar, &lastLogin, &item.User.CreatedAt, &item.User.UpdatedAt,
		&item.CredentialID, &item.PasswordHash, &item.PasswordAlgorithm,
		&item.PasswordUpdatedAt, &item.CredentialCreated, &item.CredentialUpdated,
	)
	item.User.Avatar = avatar.String
	if lastLogin.Valid {
		value := lastLogin.Time.UTC()
		item.User.LastLoginAt = &value
	}
	item.User.CreatedAt = item.User.CreatedAt.UTC()
	item.User.UpdatedAt = item.User.UpdatedAt.UTC()
	item.PasswordUpdatedAt = item.PasswordUpdatedAt.UTC()
	item.CredentialCreated = item.CredentialCreated.UTC()
	item.CredentialUpdated = item.CredentialUpdated.UTC()
	return item, err
}
