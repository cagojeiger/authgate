package storage

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (s *Storage) CreateUserWithIdentity(ctx context.Context, email string, emailVerified bool, name, avatarURL, provider, providerUserID, providerEmail string) (*User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := s.clock.Now()
	userID := s.idgen.NewUUID()

	_, err = tx.ExecContext(ctx,
		`INSERT INTO users (id, email, email_verified, name, avatar_url, status, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,'active',$6,$6)`,
		userID, email, emailVerified, name, avatarURL, now,
	)
	if err != nil {
		if isUniqueViolation(err, "users_email_key") {
			return nil, ErrEmailConflict
		}
		return nil, err
	}

	identityID := s.idgen.NewUUID()
	_, err = tx.ExecContext(ctx,
		`INSERT INTO user_identities (id, user_id, provider, provider_user_id, provider_email, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		identityID, userID, provider, providerUserID, providerEmail, now,
	)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return &User{
		ID:            userID,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		Status:        "active",
		CreatedAt:     now,
		UpdatedAt:     now,
	}, nil
}

func (s *Storage) GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*User, error) {
	u := &User{}
	err := s.db.QueryRowContext(ctx,
		`SELECT u.id, u.email, u.email_verified, u.name, u.avatar_url, u.status,
		        u.terms_version, u.terms_accepted_at, u.privacy_version, u.privacy_accepted_at,
		        u.created_at, u.updated_at
		 FROM users u
		 JOIN user_identities ui ON u.id = ui.user_id
		 WHERE ui.provider = $1 AND ui.provider_user_id = $2`,
		provider, providerUserID,
	).Scan(&u.ID, &u.Email, &u.EmailVerified, &u.Name, &u.AvatarURL, &u.Status,
		&u.TermsVersion, &u.TermsAcceptedAt, &u.PrivacyVersion, &u.PrivacyAcceptedAt,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Storage) getUserByID(ctx context.Context, tx *sql.Tx, userID string) (*User, error) {
	u := &User{}
	err := tx.QueryRowContext(ctx,
		`SELECT id, email, email_verified, name, status,
		        terms_version, terms_accepted_at, privacy_version, privacy_accepted_at
		 FROM users WHERE id = $1`, userID,
	).Scan(&u.ID, &u.Email, &u.EmailVerified, &u.Name, &u.Status,
		&u.TermsVersion, &u.TermsAcceptedAt, &u.PrivacyVersion, &u.PrivacyAcceptedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// RecoverUser atomically recovers a pending_deletion user to active.
// Uses SELECT FOR UPDATE to prevent race conditions.
func (s *Storage) RecoverUser(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := s.clock.Now()
	var status string
	err = tx.QueryRowContext(ctx,
		`SELECT status FROM users WHERE id = $1 FOR UPDATE`, userID,
	).Scan(&status)
	if err != nil {
		return err
	}
	if status != "pending_deletion" {
		return tx.Commit() // Not pending_deletion, nothing to do
	}

	_, err = tx.ExecContext(ctx,
		`UPDATE users SET status = 'active', deletion_requested_at = NULL, deletion_scheduled_at = NULL, updated_at = $1
		 WHERE id = $2`, now, userID,
	)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Storage) AcceptTerms(ctx context.Context, userID, termsVersion, privacyVersion string) error {
	now := s.clock.Now()
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET terms_version = $1, terms_accepted_at = $2, privacy_version = $3, privacy_accepted_at = $2, updated_at = $2
		 WHERE id = $4`,
		termsVersion, now, privacyVersion, userID,
	)
	return err
}

func (s *Storage) CompleteAuthRequest(ctx context.Context, authRequestID, userID string) error {
	now := s.clock.Now()
	_, err := s.db.ExecContext(ctx,
		`UPDATE auth_requests SET subject = $1, auth_time = $2, done = true WHERE id = $3`,
		userID, now, authRequestID,
	)
	return err
}

func (s *Storage) setUserinfo(ctx context.Context, userinfo *oidc.UserInfo, userID string, scopes []string) error {
	u := &User{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, email_verified, name FROM users WHERE id = $1`, userID,
	).Scan(&u.ID, &u.Email, &u.EmailVerified, &u.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}

	for _, scope := range scopes {
		switch scope {
		case "openid":
			userinfo.Subject = u.ID
		case "email":
			userinfo.Email = u.Email
			userinfo.EmailVerified = oidc.Bool(u.EmailVerified)
		case "profile":
			userinfo.Name = u.Name
		}
	}
	return nil
}

// isUniqueViolation checks if a PostgreSQL error is a unique constraint violation.
func isUniqueViolation(err error, constraintName string) bool {
	msg := err.Error()
	return strings.Contains(msg, "23505") || strings.Contains(msg, constraintName)
}

// SetUserStatus sets a user's status directly. For testing and admin operations.
func (s *Storage) SetUserStatus(ctx context.Context, userID, status string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET status = $1, updated_at = $2 WHERE id = $3`,
		status, s.clock.Now(), userID,
	)
	return err
}

// DisableUser sets a user's status to disabled.
func (s *Storage) DisableUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET status = 'disabled', updated_at = $1 WHERE id = $2`,
		s.clock.Now(), userID,
	)
	return err
}

// CreateTestAuthRequest creates a minimal auth request for testing purposes.
// Returns the UUID id assigned to the auth request.
func (s *Storage) CreateTestAuthRequest(ctx context.Context, label string) (string, error) {
	id := s.idgen.NewUUID()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_requests (id, client_id, redirect_uri, scopes, expires_at, created_at)
		 VALUES ($1, 'test-app', 'http://localhost/callback', '{openid}', $2, $3)`,
		id, s.clock.Now().Add(10*time.Minute), s.clock.Now(),
	)
	return id, err
}

// Session management

func (s *Storage) CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	sessionID := s.idgen.NewUUID()
	now := s.clock.Now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES ($1,$2,$3,$4)`,
		sessionID, userID, now.Add(ttl), now,
	)
	return sessionID, err
}

func (s *Storage) GetValidSession(ctx context.Context, sessionID string) (*User, error) {
	u := &User{}
	now := s.clock.Now()
	err := s.db.QueryRowContext(ctx,
		`SELECT u.id, u.email, u.email_verified, u.name, u.avatar_url, u.status,
		        u.terms_version, u.terms_accepted_at, u.privacy_version, u.privacy_accepted_at,
		        u.created_at, u.updated_at
		 FROM sessions s JOIN users u ON s.user_id = u.id
		 WHERE s.id = $1 AND s.expires_at > $2 AND s.revoked_at IS NULL`,
		sessionID, now,
	).Scan(&u.ID, &u.Email, &u.EmailVerified, &u.Name, &u.AvatarURL, &u.Status,
		&u.TermsVersion, &u.TermsAcceptedAt, &u.PrivacyVersion, &u.PrivacyAcceptedAt,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}
