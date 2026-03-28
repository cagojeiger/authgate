package storage

import (
	"context"
	"time"

	"authgate/internal/domain"
	"github.com/google/uuid"
)

type AuthCode struct {
	ID          uuid.UUID
	CodeHash    string
	ClientID    string
	UserID      uuid.UUID
	SessionID   uuid.UUID
	RedirectURI string
	Scopes      []string
	Challenge   string
	Method      string
	Nonce       string
	State       string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

func (db *DB) CreateAuthCode(ctx context.Context, code string, clientID string, userID, sessionID uuid.UUID, redirectURI string, scopes []string, challenge, nonce, state string) (*AuthCode, error) {
	authCode := &AuthCode{
		ID:          uuid.New(),
		CodeHash:    domain.HashToken(code),
		ClientID:    clientID,
		UserID:      userID,
		SessionID:   sessionID,
		RedirectURI: redirectURI,
		Scopes:      scopes,
		Challenge:   challenge,
		Method:      "S256",
		Nonce:       nonce,
		State:       state,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		CreatedAt:   time.Now(),
	}

	_, err := db.pool.Exec(ctx, `
		INSERT INTO auth_codes (id, code_hash, client_id, user_id, session_id, redirect_uri, scopes, pkce_challenge, pkce_method, nonce, state, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`, authCode.ID, authCode.CodeHash, authCode.ClientID, authCode.UserID, authCode.SessionID, authCode.RedirectURI, authCode.Scopes, authCode.Challenge, authCode.Method, authCode.Nonce, authCode.State, authCode.ExpiresAt, authCode.CreatedAt)

	if err != nil {
		return nil, err
	}
	return authCode, nil
}

func (db *DB) GetAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	codeHash := domain.HashToken(code)
	ac := &AuthCode{}
	err := db.pool.QueryRow(ctx, `
		SELECT id, code_hash, client_id, user_id, session_id, redirect_uri, scopes, pkce_challenge, pkce_method, nonce, state, expires_at, created_at
		FROM auth_codes
		WHERE code_hash = $1 AND used_at IS NULL AND expires_at > NOW()
	`, codeHash).Scan(&ac.ID, &ac.CodeHash, &ac.ClientID, &ac.UserID, &ac.SessionID, &ac.RedirectURI, &ac.Scopes, &ac.Challenge, &ac.Method, &ac.Nonce, &ac.State, &ac.ExpiresAt, &ac.CreatedAt)

	if err != nil {
		return nil, err
	}
	return ac, nil
}

func (db *DB) MarkAuthCodeUsed(ctx context.Context, id uuid.UUID) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE auth_codes SET used_at = NOW() WHERE id = $1
	`, id)
	return err
}
