package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/db/storeq"
)

func (s *Storage) CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	// The session cookie carries a high-entropy opaque token; the DB stores
	// only its hash (ADR-002). sessions.id stays an internal PK (no external
	// FK), so lookups go through token_hash, not the bearer.
	token, err := s.idgen.NewOpaqueToken()
	if err != nil {
		return "", err
	}
	now := s.clock.Now()
	if err := storeq.New(s.db).InsertSession(ctx, storeq.InsertSessionParams{
		ID:        s.idgen.NewUUID(),
		UserID:    userID,
		TokenHash: sql.NullString{String: s.sessionAtRest(token), Valid: true},
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}); err != nil {
		return "", err
	}
	return token, nil
}

// SessionAuthTime returns when the still-valid session was created — the time
// its owner last authenticated upstream. Callers use it as auth_time when they
// reuse a session, and to enforce max_age.
func (s *Storage) SessionAuthTime(ctx context.Context, sessionID string) (time.Time, error) {
	createdAt, err := storeq.New(s.db).GetValidSessionCreatedAt(ctx, storeq.GetValidSessionCreatedAtParams{
		TokenHash: s.sessionAtRest(sessionID),
		ExpiresAt: s.clock.Now(),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, ErrNotFound
	}
	if err != nil {
		return time.Time{}, err
	}
	return createdAt, nil
}

func (s *Storage) GetValidSession(ctx context.Context, sessionID string) (*User, error) {
	now := s.clock.Now()
	row, err := storeq.New(s.db).GetValidSessionUser(ctx, storeq.GetValidSessionUserParams{
		TokenHash: s.sessionAtRest(sessionID),
		ExpiresAt: now,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	email, name, err := s.pii().resolveUser(row.ID, row.EmailCiphertext, row.EmailNonce, row.EmailEncKeyID, row.EmailEncVersion, row.NameCiphertext, row.NameNonce, row.NameEncKeyID, row.NameEncVersion)
	if err != nil {
		return nil, err
	}
	user := buildFullUser(row.ID, email, row.EmailVerified, name, row.Status, row.CreatedAt, row.UpdatedAt)
	user.HostedDomain = row.HostedDomain
	if err := requireUsableUser(user); err != nil {
		return user, err
	}
	return user, nil
}

// requireUsableUser rejects users in terminal states (`disabled`, `deleted`).
// `active` and `pending_deletion` pass through because the channel × status
// matrix in service.CheckAccess still has nuanced handling for the latter
// (browser-channel recovery). The returned user is non-nil so the caller
// can emit channel-aware audit metadata before propagating the rejection.
func requireUsableUser(u *User) error {
	if u == nil {
		return errors.New("nil user")
	}
	switch u.Status {
	case "disabled", "deleted":
		return ErrUserAccountClosed
	}
	return nil
}

// TerminateSession revokes the user's server-side session rows only; per OIDC
// RP-Initiated Logout 1.0 §2 vs RFC 7009 it does NOT revoke refresh tokens (RPs
// must call /oauth/revoke). See docs/spec/005-token-lifecycle.md "Logout vs.
// Revoke".
func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	n, err := storeq.New(s.db).RevokeSessionsByUserID(ctx, storeq.RevokeSessionsByUserIDParams{
		RevokedAt: sql.NullTime{Time: s.clock.Now(), Valid: true},
		UserID:    userID,
	})
	if err != nil {
		return err
	}
	// Audit a logout only when it ended something, so replayed or duplicate
	// logout requests do not add rows for sessions that were already gone.
	if n == 0 {
		return nil
	}
	info := clientinfo.FromContext(ctx)
	// Emit client_id + client_name so auth.logout carries client context
	// (audit-011 invariant). clientID arrives from zitadel's logout dispatch.
	s.AuditLog(ctx, &userID, EventAuthLogout, info.IP, info.UserAgent, map[string]any{
		"client_id":   clientID,
		"client_name": s.auditClientName(ctx, clientID),
	})
	return nil
}
