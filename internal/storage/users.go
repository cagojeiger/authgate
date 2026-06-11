package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/kangheeyong/authgate/internal/db/storeq"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type CreateUserWithIdentityInput struct {
	Email          string
	EmailVerified  bool
	Name           string
	Provider       string
	ProviderUserID string
}

func (s *Storage) CreateUserWithIdentity(ctx context.Context, input CreateUserWithIdentityInput) (*User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	now := s.clock.Now()
	userID := s.idgen.NewUUID()
	qtx := storeq.New(tx)

	err = s.insertUserForSignup(ctx, qtx, userID, input, now)
	if err != nil {
		// Plaintext path conflicts on users_email_key; encrypted path on the
		// email_hash unique index.
		if isUniqueViolation(err, "users_email_key") || isUniqueViolation(err, usersEmailHashKey) {
			return nil, ErrEmailConflict
		}
		return nil, err
	}

	if err := s.insertIdentityForSignup(ctx, qtx, userID, input, now); err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return &User{
		ID:            userID,
		Email:         input.Email,
		EmailVerified: input.EmailVerified,
		Name:          input.Name,
		Status:        "active",
		CreatedAt:     now,
		UpdatedAt:     now,
	}, nil
}

func (s *Storage) insertUserForSignup(ctx context.Context, qtx *storeq.Queries, userID string, input CreateUserWithIdentityInput, now time.Time) error {
	params := storeq.InsertUserParams{
		ID:            userID,
		EmailVerified: input.EmailVerified,
		CreatedAt:     now,
	}
	// Encrypt email/name when keys are configured; otherwise keep the legacy
	// plaintext path (ADR-002, keys-gated).
	if s.keys != nil {
		if err := s.applyUserPIIEncryption(&params, userID, input.Email, input.Name); err != nil {
			return err
		}
	} else {
		params.Email = nullStr(input.Email)
		params.Name = nullStr(input.Name)
	}
	return qtx.InsertUser(ctx, params)
}

func (s *Storage) insertIdentityForSignup(ctx context.Context, qtx *storeq.Queries, userID string, input CreateUserWithIdentityInput, now time.Time) error {
	params := storeq.InsertUserIdentityParams{
		ID:        s.idgen.NewUUID(),
		UserID:    userID,
		Provider:  input.Provider,
		CreatedAt: now,
	}
	// Encrypt the provider subject when keys are configured; otherwise keep the
	// legacy plaintext path (ADR-002, keys-gated).
	if s.keys != nil {
		cols, err := s.encryptProviderSub(userID, input.Provider, input.ProviderUserID)
		if err != nil {
			return err
		}
		cols.applyTo(&params)
	} else {
		params.ProviderUserID = sql.NullString{String: input.ProviderUserID, Valid: true}
	}
	return qtx.InsertUserIdentity(ctx, params)
}

func (s *Storage) GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*User, error) {
	q := storeq.New(s.db)
	if s.keys != nil {
		row, err := q.GetUserByProviderSubHash(ctx, storeq.GetUserByProviderSubHashParams{
			Provider:        provider,
			ProviderSubHash: sql.NullString{String: s.keys.ProviderSubHash(provider, providerUserID), Valid: true},
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		email, name, err := s.resolveUserPII(row.ID, row.Email, row.EmailCiphertext, row.EmailNonce, row.EmailEncKeyID, row.EmailEncVersion, row.Name, row.NameCiphertext, row.NameNonce, row.NameEncKeyID, row.NameEncVersion)
		if err != nil {
			return nil, err
		}
		return buildFullUser(row.ID, email, row.EmailVerified, name, row.Status, row.CreatedAt, row.UpdatedAt), nil
	}
	row, err := q.GetUserByProviderIdentity(ctx, storeq.GetUserByProviderIdentityParams{
		Provider:       provider,
		ProviderUserID: sql.NullString{String: providerUserID, Valid: true},
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	email, name, err := s.resolveUserPII(row.ID, row.Email, row.EmailCiphertext, row.EmailNonce, row.EmailEncKeyID, row.EmailEncVersion, row.Name, row.NameCiphertext, row.NameNonce, row.NameEncKeyID, row.NameEncVersion)
	if err != nil {
		return nil, err
	}
	return buildFullUser(row.ID, email, row.EmailVerified, name, row.Status, row.CreatedAt, row.UpdatedAt), nil
}

func (s *Storage) getUserByID(ctx context.Context, tx *sql.Tx, userID string) (*User, error) {
	row, err := storeq.New(tx).GetUserForTxByID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	email, name, err := s.resolveUserPII(row.ID, row.Email, row.EmailCiphertext, row.EmailNonce, row.EmailEncKeyID, row.EmailEncVersion, row.Name, row.NameCiphertext, row.NameNonce, row.NameEncKeyID, row.NameEncVersion)
	if err != nil {
		return nil, err
	}
	return buildCoreUser(row.ID, email, row.EmailVerified, name, row.Status), nil
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
	email, name, err := s.resolveUserPII(row.ID, row.Email, row.EmailCiphertext, row.EmailNonce, row.EmailEncKeyID, row.EmailEncVersion, row.Name, row.NameCiphertext, row.NameNonce, row.NameEncKeyID, row.NameEncVersion)
	if err != nil {
		return nil, err
	}
	return buildFullUser(row.ID, email, row.EmailVerified, name, row.Status, row.CreatedAt, row.UpdatedAt), nil
}

// RecoverUser recovers a pending_deletion user to active.
// If the user is not pending_deletion, it is a no-op.
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
	email, name, err := s.resolveUserPII(row.ID, row.Email, row.EmailCiphertext, row.EmailNonce, row.EmailEncKeyID, row.EmailEncVersion, row.Name, row.NameCiphertext, row.NameNonce, row.NameEncKeyID, row.NameEncVersion)
	if err != nil {
		return err
	}
	u := &User{
		ID:            row.ID,
		Email:         email,
		EmailVerified: row.EmailVerified,
		Name:          nullStringToString(name),
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
	return s.setUserStatus(ctx, userID, status)
}

// RequestDeletion sets a user to pending_deletion and revokes all refresh tokens. Single TX.
// Sessions are intentionally NOT revoked here — they expire naturally (24h TTL).
// Revoking refresh tokens immediately blocks new access token issuance, which is sufficient
// per industry standard (Auth0, Okta pattern).
//
// #183: the UPDATE is gated on `status='active'` so an admin-set `disabled`
// or a cleanup-set `deleted` cannot be silently overwritten. If the gate
// rejects the row, we re-read the user inside the same TX:
//   - `pending_deletion` → idempotent success (already in target state)
//   - `disabled` / `deleted` → ErrUserAccountClosed (caller emits 403)
//   - any other state → an error
//
// Returns the live status read inside the TX when ErrUserAccountClosed is
// returned, so the caller can record the *actual* state in audit logs
// rather than the stale session-snapshot status. Empty string otherwise.
func (s *Storage) RequestDeletion(ctx context.Context, userID string) (string, error) {
	now := s.clock.Now()
	scheduledAt := now.Add(30 * 24 * time.Hour)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	qtx := storeq.New(tx)

	rows, err := markUserPendingDeletion(ctx, qtx, userID, now, scheduledAt)
	if err != nil {
		return "", err
	}

	if rows == 0 {
		current, err := s.getUserByID(ctx, tx, userID)
		if err != nil {
			return "", err
		}
		switch current.Status {
		case "pending_deletion":
			// Idempotent: already in target state. Re-running the refresh-token
			// revoke is safe (`WHERE revoked_at IS NULL`) and protects against
			// the case where the previous transition crashed between the
			// status flip and the token revoke.
			if err := revokeActiveRefreshTokensForDeletion(ctx, qtx, userID, now); err != nil {
				return "", err
			}
			return "", tx.Commit()
		case "disabled", "deleted":
			return current.Status, ErrUserAccountClosed
		default:
			return current.Status, errors.New("unexpected user status for deletion: " + current.Status)
		}
	}

	if err := revokeActiveRefreshTokensForDeletion(ctx, qtx, userID, now); err != nil {
		return "", err
	}

	return "", tx.Commit()
}

func markUserPendingDeletion(ctx context.Context, qtx *storeq.Queries, userID string, now, scheduledAt time.Time) (int64, error) {
	return qtx.MarkUserPendingDeletionByID(ctx, storeq.MarkUserPendingDeletionByIDParams{
		DeletionRequestedAt: sql.NullTime{Time: now, Valid: true},
		DeletionScheduledAt: sql.NullTime{Time: scheduledAt, Valid: true},
		ID:                  userID,
	})
}

func revokeActiveRefreshTokensForDeletion(ctx context.Context, qtx *storeq.Queries, userID string, now time.Time) error {
	return qtx.RevokeActiveRefreshTokensByUserID(ctx, storeq.RevokeActiveRefreshTokensByUserIDParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		UserID:    userID,
	})
}

// DisableUser sets a user's status to disabled.
func (s *Storage) DisableUser(ctx context.Context, userID string) error {
	return s.setUserStatus(ctx, userID, "disabled")
}

func (s *Storage) setUserStatus(ctx context.Context, userID, status string) error {
	return storeq.New(s.db).SetUserStatusByID(ctx, storeq.SetUserStatusByIDParams{
		Status:    status,
		UpdatedAt: s.clock.Now(),
		ID:        userID,
	})
}

// CreateTestAuthRequest creates a minimal auth request for testing purposes.
// Returns the UUID id assigned to the auth request.
//
// The auth_request is bound to client_id "test-app" (registered with
// login_channel="browser" so the channel-binding guard accepts it).
func (s *Storage) CreateTestAuthRequest(ctx context.Context, label string) (string, error) {
	s.LoadClients([]ClientConfigEntry{{ClientID: "test-app", Name: "Test App", LoginChannel: "browser"}})
	id := s.idgen.NewUUID()
	err := storeq.New(s.db).InsertTestAuthRequest(ctx, storeq.InsertTestAuthRequestParams{
		ID:        id,
		State:     sql.NullString{String: label, Valid: true},
		ExpiresAt: s.clock.Now().Add(10 * time.Minute),
		CreatedAt: s.clock.Now(),
	})
	return id, err
}

// CreateTestAuthRequestWithResource creates a minimal auth request with a resource field set,
// for testing MCP flows that require resource binding validation.
//
// The auth_request is bound to client_id "test-mcp-app" (registered with
// login_channel="mcp" so the channel-binding guard accepts it).
func (s *Storage) CreateTestAuthRequestWithResource(ctx context.Context, label, resource string) (string, error) {
	s.LoadClients([]ClientConfigEntry{{ClientID: "test-mcp-app", Name: "Test MCP App", LoginChannel: "mcp"}})
	id := s.idgen.NewUUID()
	now := s.clock.Now()
	err := storeq.New(s.db).InsertTestAuthRequestWithResource(ctx, storeq.InsertTestAuthRequestWithResourceParams{
		ID:        id,
		State:     sql.NullString{String: label, Valid: true},
		Resource:  sql.NullString{String: resource, Valid: true},
		ExpiresAt: now.Add(10 * time.Minute),
		CreatedAt: now,
	})
	return id, err
}

// Session management

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
	email, name, err := s.resolveUserPII(row.ID, row.Email, row.EmailCiphertext, row.EmailNonce, row.EmailEncKeyID, row.EmailEncVersion, row.Name, row.NameCiphertext, row.NameNonce, row.NameEncKeyID, row.NameEncVersion)
	if err != nil {
		return nil, err
	}
	user := buildFullUser(row.ID, email, row.EmailVerified, name, row.Status, row.CreatedAt, row.UpdatedAt)
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

func buildCoreUser(id, email string, emailVerified bool, name sql.NullString, status string) *User {
	return &User{
		ID:            id,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          nullStringToString(name),
		Status:        status,
	}
}

func buildFullUser(id, email string, emailVerified bool, name sql.NullString, status string, createdAt, updatedAt time.Time) *User {
	return &User{
		ID:            id,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          nullStringToString(name),
		Status:        status,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}
}
