package testutil

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/kangheeyong/authgate/internal/db/migrator"
)

// SetupPostgres starts a PostgreSQL container, runs migrations via the
// same migrator package authgate uses in production, and returns a
// *sql.DB. The container is automatically cleaned up when the test ends.
func SetupPostgres(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()

	migrationPath := findMigrations(t)

	container, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("authgate_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("terminate postgres container: %v", err)
		}
	})

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	for i := 0; i < 30; i++ {
		if err := db.Ping(); err == nil {
			if err := migrator.Run(db, migrationPath); err != nil {
				t.Fatalf("apply migrations: %v", err)
			}
			return db
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("db not ready after 15s")
	return nil
}

// findMigrations walks up from cwd to find the migrations/ directory.
func findMigrations(t *testing.T) string {
	t.Helper()

	if p := os.Getenv("AUTHGATE_MIGRATIONS_PATH"); p != "" {
		return p
	}

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	for {
		candidate := filepath.Join(dir, "migrations")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	t.Fatal("migrations/ directory not found — set AUTHGATE_MIGRATIONS_PATH")
	return ""
}
