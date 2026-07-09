// Package storage owns the SQLite database: schema/migrations and the report
// repository. The scraper writes; the server reads. WAL mode allows concurrent
// readers with a single writer on a shared PVC (see docs/03-database.md).
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the sql.DB handle and its file path.
type DB struct {
	sql  *sql.DB
	path string
}

// Open opens (creating if needed) the SQLite database at dir/trivy.db, applies
// pragmas for WAL + sane concurrency, and runs migrations.
func Open(ctx context.Context, dir string) (*DB, error) {
	path := filepath.Join(dir, "trivy.db")
	dsn := "file:" + path + "?" + url.Values{
		"_pragma": {
			"journal_mode(WAL)",
			"busy_timeout(5000)",
			"foreign_keys(on)",
			"synchronous(NORMAL)",
		},
	}.Encode()

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	// modernc/sqlite serializes writes internally; keeping the pool small avoids
	// "database is locked" churn under the single-writer model.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("ping sqlite %s: %w", path, err)
	}
	if err := migrate(ctx, sqlDB); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &DB{sql: sqlDB, path: path}, nil
}

// OpenMemory opens an in-memory database for tests (shared cache so the single
// connection sees the schema).
func OpenMemory(ctx context.Context) (*DB, error) {
	dsn := "file:trivy_mem?mode=memory&cache=shared&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open memory sqlite: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := migrate(ctx, sqlDB); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &DB{sql: sqlDB, path: ":memory:"}, nil
}

// SQL returns the underlying handle.
func (d *DB) SQL() *sql.DB { return d.sql }

// Path returns the database file path.
func (d *DB) Path() string { return d.path }

// Close closes the database.
func (d *DB) Close() error { return d.sql.Close() }
