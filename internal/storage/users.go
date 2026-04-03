package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/kangheeyong/authgate/internal/storage/storeq"
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
	qtx := storeq.New(tx)

	err = qtx.InsertUser(ctx, storeq.InsertUserParams{
		ID:            userID,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          sql.NullString{String: name, Valid: true},
		AvatarUrl:     sql.NullString{String: avatarURL, Valid: true},
		CreatedAt:     now,
	})
	if err != nil {
		if isUniqueViolation(err, "users_email_key") {
			return nil, ErrEmailConflict
		}
		return nil, err
	}

	identityID := s.idgen.NewUUID()
	err = qtx.InsertUserIdentity(ctx, storeq.InsertUserIdentityParams{
		ID:             identityID,
		UserID:         userID,
		Provider:       provider,
		ProviderUserID: providerUserID,
		ProviderEmail:  sql.NullString{String: providerEmail, Valid: true},
		CreatedAt:      now,
	})
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
	row, err := storeq.New(s.db).GetUserByProviderIdentity(ctx, storeq.GetUserByProviderIdentityParams{
		Provider:       provider,
		ProviderUserID: providerUserID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &User{
		ID:            row.ID,
		Email:         row.Email,
		EmailVerified: row.EmailVerified,
		Name:          nullStringToString(row.Name),
		AvatarURL:     nullStringToPtr(row.AvatarUrl),
		Status:        row.Status,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}, nil
}

func (s *Storage) getUserByID(ctx context.Context, tx *sql.Tx, userID string) (*User, error) {
	row, err := storeq.New(tx).GetUserForTxByID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &User{
		ID:            row.ID,
		Email:         row.Email,
		EmailVerified: row.EmailVerified,
		Name:          nullStringToString(row.Name),
		Status:        row.Status,
	}, nil
}

// GetUserByID returns a user by ID. Public wrapper for DB-level re-read after mutations.
func (s *Storage) GetUserByID(ctx context.Context, userID string) (*User, error) {
	row, err := storeq.New(s.db).GetUserByID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &User{
		ID:            row.ID,
		Email:         row.Email,
		EmailVerified: row.EmailVerified,
		Name:          nullStringToString(row.Name),
		AvatarURL:     nullStringToPtr(row.AvatarUrl),
		Status:        row.Status,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}, nil
}

// RecoverUser atomically recovers a pending_deletion user to active.
// Uses SELECT FOR UPDATE to prevent race conditions.
func (s *Storage) RecoverUser(ctx context.Context, userID string) error {
	return storeq.New(s.db).RecoverPendingDeletionUserByID(ctx, storeq.RecoverPendingDeletionUserByIDParams{
		UpdatedAt: s.clock.Now(),
		ID:        userID,
	})
}

func (s *Storage) CompleteAuthRequest(ctx context.Context, authRequestID, userID string) error {
	now := s.clock.Now()
	rows, err := storeq.New(s.db).CompleteAuthRequestByID(ctx, storeq.CompleteAuthRequestByIDParams{
		Subject:  sql.NullString{String: userID, Valid: true},
		AuthTime: sql.NullTime{Time: now, Valid: true},
		ID:       authRequestID,
	})
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Storage) setUserinfo(ctx context.Context, userinfo *oidc.UserInfo, userID string, scopes []string) error {
	row, err := storeq.New(s.db).GetUserInfoFieldsByID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	u := &User{
		ID:            row.ID,
		Email:         row.Email,
		EmailVerified: row.EmailVerified,
		Name:          nullStringToString(row.Name),
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

// SetUserStatus sets a user's status directly. For testing and admin operations.
func (s *Storage) SetUserStatus(ctx context.Context, userID, status string) error {
	return storeq.New(s.db).SetUserStatusByID(ctx, storeq.SetUserStatusByIDParams{
		Status:    status,
		UpdatedAt: s.clock.Now(),
		ID:        userID,
	})
}

// RequestDeletion sets a user to pending_deletion and revokes all refresh tokens. Single TX.
func (s *Storage) RequestDeletion(ctx context.Context, userID string) error {
	now := s.clock.Now()
	scheduledAt := now.Add(30 * 24 * time.Hour)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	qtx := storeq.New(tx)

	err = qtx.MarkUserPendingDeletionByID(ctx, storeq.MarkUserPendingDeletionByIDParams{
		DeletionRequestedAt: sql.NullTime{Time: now, Valid: true},
		DeletionScheduledAt: sql.NullTime{Time: scheduledAt, Valid: true},
		ID:                  userID,
	})
	if err != nil {
		return err
	}

	err = qtx.RevokeActiveRefreshTokensByUserID(ctx, storeq.RevokeActiveRefreshTokensByUserIDParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		UserID:    userID,
	})
	if err != nil {
		return err
	}

	return tx.Commit()
}

// DisableUser sets a user's status to disabled.
func (s *Storage) DisableUser(ctx context.Context, userID string) error {
	return storeq.New(s.db).SetUserStatusByID(ctx, storeq.SetUserStatusByIDParams{
		Status:    "disabled",
		UpdatedAt: s.clock.Now(),
		ID:        userID,
	})
}

// CreateTestAuthRequest creates a minimal auth request for testing purposes.
// Returns the UUID id assigned to the auth request.
func (s *Storage) CreateTestAuthRequest(ctx context.Context, label string) (string, error) {
	id := s.idgen.NewUUID()
	err := storeq.New(s.db).InsertTestAuthRequest(ctx, storeq.InsertTestAuthRequestParams{
		ID:        id,
		State:     sql.NullString{String: label, Valid: true},
		ExpiresAt: s.clock.Now().Add(10 * time.Minute),
		CreatedAt: s.clock.Now(),
	})
	return id, err
}

// Session management

func (s *Storage) CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	sessionID := s.idgen.NewUUID()
	now := s.clock.Now()
	err := storeq.New(s.db).InsertSession(ctx, storeq.InsertSessionParams{
		ID:        sessionID,
		UserID:    userID,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	})
	return sessionID, err
}

func (s *Storage) GetValidSession(ctx context.Context, sessionID string) (*User, error) {
	now := s.clock.Now()
	row, err := storeq.New(s.db).GetValidSessionUser(ctx, storeq.GetValidSessionUserParams{
		ID:        sessionID,
		ExpiresAt: now,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &User{
		ID:            row.ID,
		Email:         row.Email,
		EmailVerified: row.EmailVerified,
		Name:          nullStringToString(row.Name),
		AvatarURL:     nullStringToPtr(row.AvatarUrl),
		Status:        row.Status,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}, nil
}
