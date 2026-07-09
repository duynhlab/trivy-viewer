package storage

import (
	"context"
	"database/sql"
	"fmt"
)

// migration is a single ordered, forward-only schema change.
type migration struct {
	version int
	name    string
	sql     string
}

// migrations are applied in order. During active development, edit schemaSQL and
// recreate the database (fresh PVC or delete SQLite file) rather than appending migrations.
var migrations = []migration{
	{version: 1, name: "initial_schema", sql: schemaSQL},
}

// migrate applies all pending migrations inside a transaction per migration.
func migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT NOT NULL,
			applied_at TEXT NOT NULL DEFAULT (datetime('now'))
		);`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	var current int
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	for _, mig := range migrations {
		if mig.version <= current {
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", mig.version, err)
		}
		if _, err := tx.ExecContext(ctx, mig.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d (%s): %w", mig.version, mig.name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name) VALUES (?, ?)`,
			mig.version, mig.name); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", mig.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", mig.version, err)
		}
	}
	return nil
}
