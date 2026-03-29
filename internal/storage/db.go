package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("not found")

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

// --- Users ---

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


func (db *DB) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	user := &User{}
	err := db.pool.QueryRow(ctx,
		`SELECT id, email, email_verified, name, avatar_url, status, created_at, updated_at
		 FROM users WHERE id = $1`,
		id).Scan(&user.ID, &user.PrimaryEmail, &user.EmailVerified, &user.Name, &user.AvatarURL, &user.Status, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (db *DB) GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*User, error) {
	user := &User{}
	err := db.pool.QueryRow(ctx,
		`SELECT u.id, u.email, u.email_verified, u.name, u.avatar_url, u.status, u.created_at, u.updated_at
		 FROM users u
		 JOIN user_identities ui ON u.id = ui.user_id
		 WHERE ui.provider = $1 AND ui.provider_user_id = $2`,
		provider, providerUserID).Scan(&user.ID, &user.PrimaryEmail, &user.EmailVerified, &user.Name, &user.AvatarURL, &user.Status, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query user by provider identity: %w", err)
	}
	return user, nil
}

// IsActive returns true if user status is "active"
func (u *User) IsActive() bool {
	return u.Status == "active"
}

// AcceptTerms records the user's agreement to terms and privacy policy
func (db *DB) AcceptTerms(ctx context.Context, userID uuid.UUID, termsVersion, privacyVersion string) error {
	return db.Exec(ctx,
		`UPDATE users SET terms_version = $2, terms_accepted_at = NOW(), privacy_version = $3, privacy_accepted_at = NOW(), updated_at = NOW()
		 WHERE id = $1`,
		userID, termsVersion, privacyVersion)
}

// HasAcceptedTerms checks if user has accepted the current terms version
func (db *DB) HasAcceptedTerms(ctx context.Context, userID uuid.UUID, termsVersion string) (bool, error) {
	var version *string
	err := db.pool.QueryRow(ctx,
		`SELECT terms_version FROM users WHERE id = $1`, userID).Scan(&version)
	if err != nil {
		return false, err
	}
	return version != nil && *version == termsVersion, nil
}

// RequestDeletion marks a user for deletion with a 30-day grace period
func (db *DB) RequestDeletion(ctx context.Context, userID uuid.UUID) error {
	return db.Exec(ctx,
		`UPDATE users SET status = 'pending_deletion', deletion_requested_at = NOW(),
		 deletion_scheduled_at = NOW() + INTERVAL '30 days', updated_at = NOW()
		 WHERE id = $1 AND status = 'active'`,
		userID)
}


// CancelDeletion restores a user from pending_deletion to active
func (db *DB) CancelDeletion(ctx context.Context, userID uuid.UUID) error {
	return db.Exec(ctx,
		`UPDATE users SET status = 'active', deletion_requested_at = NULL,
		 deletion_scheduled_at = NULL, updated_at = NOW()
		 WHERE id = $1 AND status = 'pending_deletion'`,
		userID)
}

// --- User Signup (atomic: user + identity in one transaction) ---

func (db *DB) CreateUserWithIdentity(ctx context.Context, email, name, avatarURL string, emailVerified bool, provider, providerUserID, providerEmail string) (*User, error) {
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

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`INSERT INTO users (id, email, email_verified, name, avatar_url, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		user.ID, user.PrimaryEmail, user.EmailVerified, user.Name, user.AvatarURL, user.Status, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO user_identities (id, user_id, provider, provider_user_id, provider_email, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.New(), user.ID, provider, providerUserID, providerEmail, time.Now())
	if err != nil {
		return nil, fmt.Errorf("insert identity: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return user, nil
}

// --- Sessions ---

type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ExpiresAt time.Time
	CreatedAt time.Time
}

func (db *DB) CreateSession(ctx context.Context, userID uuid.UUID, ttlSeconds int) (*Session, error) {
	session := &Session{
		ID:        uuid.New(),
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Duration(ttlSeconds) * time.Second),
		CreatedAt: time.Now(),
	}
	_, err := db.pool.Exec(ctx,
		`INSERT INTO sessions (id, user_id, expires_at, created_at)
		 VALUES ($1, $2, $3, $4)`,
		session.ID, session.UserID, session.ExpiresAt, session.CreatedAt)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (db *DB) GetSession(ctx context.Context, id uuid.UUID) (*Session, error) {
	session := &Session{}
	err := db.pool.QueryRow(ctx,
		`SELECT id, user_id, expires_at, created_at
		 FROM sessions WHERE id = $1 AND revoked_at IS NULL AND expires_at > NOW()`,
		id).Scan(&session.ID, &session.UserID, &session.ExpiresAt, &session.CreatedAt)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// --- Audit Log ---

func (db *DB) LogEvent(ctx context.Context, userID *uuid.UUID, eventType, ipAddress, userAgent string, metadata map[string]any) {
	db.pool.Exec(ctx,
		`INSERT INTO audit_log (user_id, event_type, ip_address, user_agent, metadata, created_at)
		 VALUES ($1, $2, $3::inet, $4, $5, NOW())`,
		userID, eventType, ipAddress, userAgent, metadata)
}
