// Package storage 负责数据库连接、迁移和 SQL 方言选择。
package storage

import (
	"fmt"
	"strings"
)

// NormalizeSQLDriver 把配置名称转换为 database/sql 驱动名。
func NormalizeSQLDriver(driver string) string {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "postgres", "postgresql", "pg", "pgx":
		return "pgx"
	default:
		return "sqlite"
	}
}

// IsSQLiteSQLDriver 判断 database/sql 驱动是否为 SQLite。
func IsSQLiteSQLDriver(driver string) bool {
	return NormalizeSQLDriver(driver) == "sqlite"
}

// MigrationDirName 返回当前驱动使用的 migration 目录。
func MigrationDirName(driver string) string {
	if NormalizeSQLDriver(driver) == "pgx" {
		return "postgres"
	}
	return "sqlite"
}

// SQLDialect 只封装 SQLite 与 PostgreSQL 真正不同的 SQL 片段。
type SQLDialect struct {
	postgres bool
}

func NewSQLDialect(driver string) SQLDialect {
	return SQLDialect{postgres: NormalizeSQLDriver(driver) == "pgx"}
}

func (d SQLDialect) Bind(index int) string {
	if d.postgres {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func (d SQLDialect) BindList(count int) string {
	items := make([]string, 0, count)
	for index := 1; index <= count; index++ {
		items = append(items, d.Bind(index))
	}
	return strings.Join(items, ", ")
}

func (d SQLDialect) ForUpdate() string {
	if d.postgres {
		return " FOR UPDATE"
	}
	return ""
}
