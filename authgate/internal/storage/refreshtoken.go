package storage

import (
	"context"
	"time"

	"authgate/internal/domain"
	"github.com/google/uuid"
)

type RefreshToken struct {
	ID        uuid.UUID
	TokenHash string
	UserID    uuid.UUID
	SessionID uuid.UUID
	ClientID  string
	Scopes    []string
	ExpiresAt time.Time
	CreatedAt time.Time
}

func (db *DB) CreateRefreshToken(ctx context.Context, token string, userID, sessionID uuid.UUID, clientID string, scopes []string, ttlSeconds int) (*RefreshToken, error) {
	rt := &RefreshToken{
		ID:        uuid.New(),
		TokenHash: domain.HashToken(token),
		UserID:    userID,
		SessionID: sessionID,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(time.Duration(ttlSeconds) * time.Second),
		CreatedAt: time.Now(),
	}

	_, err := db.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (id, token_hash, user_id, session_id, client_id, scopes, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, rt.ID, rt.TokenHash, rt.UserID, rt.SessionID, rt.ClientID, rt.Scopes, rt.ExpiresAt, rt.CreatedAt)

	if err != nil {
		return nil, err
	}
	return rt, nil
}

func (db *DB) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	tokenHash := domain.HashToken(token)
	rt := &RefreshToken{}
	err := db.pool.QueryRow(ctx, `
		SELECT id, token_hash, user_id, session_id, client_id, scopes, expires_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
	`, tokenHash).Scan(&rt.ID, &rt.TokenHash, &rt.UserID, &rt.SessionID, &rt.ClientID, &rt.Scopes, &rt.ExpiresAt, &rt.CreatedAt)

	if err != nil {
		return nil, err
	}
	return rt, nil
}

func (db *DB) RotateRefreshToken(ctx context.Context, oldID uuid.UUID, newToken string, ttlSeconds int) (*RefreshToken, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var userID, sessionID uuid.UUID
	var clientID string
	var scopes []string

	err = tx.QueryRow(ctx, `
		SELECT user_id, session_id, client_id, scopes
		FROM refresh_tokens
		WHERE id = $1 AND revoked_at IS NULL AND expires_at > NOW()
	`, oldID).Scan(&userID, &sessionID, &clientID, &scopes)

	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1
	`, oldID)
	if err != nil {
		return nil, err
	}

	newRT := &RefreshToken{
		ID:        uuid.New(),
		TokenHash: domain.HashToken(newToken),
		UserID:    userID,
		SessionID: sessionID,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(time.Duration(ttlSeconds) * time.Second),
		CreatedAt: time.Now(),
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO refresh_tokens (id, token_hash, user_id, session_id, client_id, scopes, expires_at, rotated_from_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, newRT.ID, newRT.TokenHash, newRT.UserID, newRT.SessionID, newRT.ClientID, newRT.Scopes, newRT.ExpiresAt, oldID, newRT.CreatedAt)

	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return newRT, nil
}

func (db *DB) RevokeRefreshToken(ctx context.Context, id uuid.UUID) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1
	`, id)
	return err
}
