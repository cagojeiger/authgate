// Package migrator runs database schema migrations using golang-migrate.
//
// Migrations are versioned SQL files under `migrations/` following the
// golang-migrate naming convention (`<version>_<name>.up.sql` /
// `.down.sql`). golang-migrate tracks applied versions in the
// `schema_migrations` table and uses Postgres advisory locks so that
// concurrent authgate replicas can safely call Run — only one instance
// applies pending migrations, the others become no-ops.
package migrator

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// Run applies all pending up migrations from sourcePath against the
// supplied *sql.DB. sourcePath is a filesystem path (e.g. "./migrations"
// or "/migrations") — not a file:// URL.
//
// It is safe to call from multiple processes simultaneously: the
// Postgres driver acquires an advisory lock for the duration of the
// migration run.
func Run(db *sql.DB, sourcePath string) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("migrator driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance("file://"+sourcePath, "postgres", driver)
	if err != nil {
		return fmt.Errorf("migrator init: %w", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrator up: %w", err)
	}

	version, dirty, verr := m.Version()
	if verr != nil && !errors.Is(verr, migrate.ErrNilVersion) {
		slog.Warn("migrator version lookup failed", "error", verr)
		return nil
	}
	if errors.Is(verr, migrate.ErrNilVersion) {
		slog.Info("migrations applied", "version", "none")
		return nil
	}
	slog.Info("migrations applied", "version", version, "dirty", dirty)
	return nil
}
