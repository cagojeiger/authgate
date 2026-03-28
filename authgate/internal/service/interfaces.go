package service

import (
	"context"

	"authgate/internal/storage"
	"github.com/google/uuid"
)

// SessionStore defines the interface for session management
type SessionStore interface {
	CreateSession(ctx context.Context, userID uuid.UUID, ttlSeconds int) (*storage.Session, error)
	GetSession(ctx context.Context, id uuid.UUID) (*storage.Session, error)
	RevokeSession(ctx context.Context, id uuid.UUID) error
}

// UserStore defines the interface for user management
type UserStore interface {
	CreateUser(ctx context.Context, email, name, avatarURL string, emailVerified bool) (*storage.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*storage.User, error)
	GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*storage.User, error)
	CreateUserIdentity(ctx context.Context, userID uuid.UUID, provider, providerUserID, providerEmail string, rawData []byte) error
}

// AuthCodeStore defines the interface for authorization code management
type AuthCodeStore interface {
	CreateAuthCode(ctx context.Context, code string, clientID string, userID, sessionID uuid.UUID, redirectURI string, scopes []string, challenge, nonce, state string) (*storage.AuthCode, error)
	GetAuthCode(ctx context.Context, code string) (*storage.AuthCode, error)
	MarkAuthCodeUsed(ctx context.Context, id uuid.UUID) error
}

// RefreshTokenStore defines the interface for refresh token management
type RefreshTokenStore interface {
	CreateRefreshToken(ctx context.Context, token string, userID, sessionID uuid.UUID, clientID string, scopes []string, ttlSeconds int) (*storage.RefreshToken, error)
	GetRefreshToken(ctx context.Context, token string) (*storage.RefreshToken, error)
	RotateRefreshToken(ctx context.Context, oldID uuid.UUID, newToken string, ttlSeconds int) (*storage.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, id uuid.UUID) error
}

// Pinger defines the interface for health check operations
type Pinger interface {
	Ping(ctx context.Context) error
}

// Store combines all storage interfaces for convenience
type Store interface {
	SessionStore
	UserStore
	AuthCodeStore
	RefreshTokenStore
	Pinger
}
