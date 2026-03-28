package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	pool *pgxpool.Pool
}

func New(databaseURL string) (*DB, error) {
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}
	return &DB{pool: pool}, nil
}

func (db *DB) Close() {
	db.pool.Close()
}

func (db *DB) Ping(ctx context.Context) error {
	return db.pool.Ping(ctx)
}

func (db *DB) Exec(ctx context.Context, sql string, args ...interface{}) error {
	_, err := db.pool.Exec(ctx, sql, args...)
	return err
}

func (db *DB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return db.pool.QueryRow(ctx, sql, args...)
}

type User struct {
	ID            uuid.UUID
	PrimaryEmail  string
	EmailVerified bool
	Name          string
	AvatarURL     string
	Status        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (db *DB) CreateUser(ctx context.Context, email, name, avatarURL string, emailVerified bool) (*User, error) {
	user := &User{
		ID:            uuid.New(),
		PrimaryEmail:  email,
		EmailVerified: emailVerified,
		Name:          name,
		AvatarURL:     avatarURL,
		Status:        "active",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	_, err := db.pool.Exec(ctx, `
		INSERT INTO users (id, primary_email, email_verified, name, avatar_url, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, user.ID, user.PrimaryEmail, user.EmailVerified, user.Name, user.AvatarURL, user.Status, user.CreatedAt, user.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

func (db *DB) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	user := &User{}
	err := db.pool.QueryRow(ctx, `
		SELECT id, primary_email, email_verified, name, avatar_url, status, created_at, updated_at
		FROM users WHERE id = $1
	`, id).Scan(&user.ID, &user.PrimaryEmail, &user.EmailVerified, &user.Name, &user.AvatarURL, &user.Status, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return nil, err
	}
	return user, nil
}

type UserIdentity struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	Provider       string
	ProviderUserID string
	ProviderEmail  string
}

func (db *DB) GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*User, error) {
	user := &User{}
	err := db.pool.QueryRow(ctx, `
		SELECT u.id, u.primary_email, u.email_verified, u.name, u.avatar_url, u.status, u.created_at, u.updated_at
		FROM users u
		JOIN user_identities ui ON u.id = ui.user_id
		WHERE ui.provider = $1 AND ui.provider_user_id = $2
	`, provider, providerUserID).Scan(&user.ID, &user.PrimaryEmail, &user.EmailVerified, &user.Name, &user.AvatarURL, &user.Status, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return nil, err
	}
	return user, nil
}

func (db *DB) CreateUserIdentity(ctx context.Context, userID uuid.UUID, provider, providerUserID, providerEmail string, rawData []byte) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO user_identities (id, user_id, provider, provider_user_id, provider_email, provider_raw, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, uuid.New(), userID, provider, providerUserID, providerEmail, rawData, time.Now())
	return err
}
