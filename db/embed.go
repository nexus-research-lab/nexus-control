// Package db 暴露随 Control 二进制发布的数据库迁移。
package db

import "embed"

// Migrations 包含 SQLite 与 PostgreSQL schema。
//
//go:embed migrations/sqlite/*.sql migrations/postgres/*.sql
var Migrations embed.FS
