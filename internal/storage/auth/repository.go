package auth

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/nexus-research-lab/nexus-control/internal/config"
	"github.com/nexus-research-lab/nexus-control/internal/storage"
)

// Repository 封装 Control 认证域的 SQLite/PostgreSQL SQL。
type Repository struct {
	db      *sql.DB
	dialect storage.SQLDialect
}

func NewRepository(cfg config.Config, database *sql.DB) *Repository {
	return &Repository{db: database, dialect: storage.NewSQLDialect(cfg.DatabaseDriver)}
}

func (r *Repository) Ping(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

func (r *Repository) bind(index int) string {
	return r.dialect.Bind(index)
}

func (r *Repository) lockControlState(ctx context.Context, tx *sql.Tx) error {
	var singleton int
	return tx.QueryRowContext(ctx,
		`SELECT singleton_id FROM control_state WHERE singleton_id = `+r.bind(1)+r.dialect.ForUpdate(),
		1,
	).Scan(&singleton)
}

func (r *Repository) lockDeployment(ctx context.Context, tx *sql.Tx, deploymentID string) error {
	var value string
	err := tx.QueryRowContext(ctx,
		`SELECT deployment_id FROM deployments WHERE deployment_id = `+r.bind(1)+r.dialect.ForUpdate(),
		deploymentID,
	).Scan(&value)
	if err == sql.ErrNoRows {
		return ErrNotFound
	}
	return err
}

func nullableString(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}

func nullTimePointer(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	normalized := value.Time.UTC()
	return &normalized
}

type rowScanner interface {
	Scan(...any) error
}
