package storage

import (
	"context"
	"time"

	"github.com/google/uuid"
)

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

	_, err := db.pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, expires_at, created_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5)
	`, session.ID, session.UserID, session.ExpiresAt, session.CreatedAt, session.CreatedAt)

	if err != nil {
		return nil, err
	}
	return session, nil
}

func (db *DB) GetSession(ctx context.Context, id uuid.UUID) (*Session, error) {
	session := &Session{}
	err := db.pool.QueryRow(ctx, `
		SELECT id, user_id, expires_at, created_at
		FROM sessions
		WHERE id = $1 AND revoked_at IS NULL AND expires_at > NOW()
	`, id).Scan(&session.ID, &session.UserID, &session.ExpiresAt, &session.CreatedAt)

	if err != nil {
		return nil, err
	}
	return session, nil
}

func (db *DB) RevokeSession(ctx context.Context, id uuid.UUID) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE sessions SET revoked_at = NOW() WHERE id = $1
	`, id)
	return err
}
