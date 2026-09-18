package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

type CreateUserWithIdentityInput struct {
	Email          string
	EmailVerified  bool
	Name           string
	Provider       string
	ProviderUserID string
	// HostedDomain is the Google hosted domain of the signup login; empty for
	// accounts without one.
	HostedDomain string
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
		// Email uniqueness is enforced by the email_hash unique index.
		if isUniqueViolation(err, usersEmailHashKey) {
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
		HostedDomain:  input.HostedDomain,
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
	// PII is always encrypted at rest (ADR-002); keys are mandatory.
	if s.keys == nil {
		return ErrEncryptionNotConfigured
	}
	if err := s.pii().applyUserEncryption(&params, userID, input.Email, input.Name); err != nil {
		return err
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
	// The provider subject is always encrypted at rest (ADR-002); keys are mandatory.
	if s.keys == nil {
		return ErrEncryptionNotConfigured
	}
	cols, err := s.pii().encryptProviderSub(userID, input.Provider, input.ProviderUserID)
	if err != nil {
		return err
	}
	cols.applyTo(&params)
	params.HostedDomain = nullableString(input.HostedDomain)
	return qtx.InsertUserIdentity(ctx, params)
}

func (s *Storage) GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*User, error) {
	q := storeq.New(s.db)
	if s.keys == nil {
		return nil, ErrEncryptionNotConfigured
	}
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
	email, name, err := s.pii().resolveUser(row.ID, row.EmailCiphertext, row.EmailNonce, row.EmailEncKeyID, row.EmailEncVersion, row.NameCiphertext, row.NameNonce, row.NameEncKeyID, row.NameEncVersion)
	if err != nil {
		return nil, err
	}
	user := buildFullUser(row.ID, email, row.EmailVerified, name, row.Status, row.CreatedAt, row.UpdatedAt)
	user.HostedDomain = row.HostedDomain.String
	return user, nil
}

// SetIdentityHostedDomain records the Google hosted domain seen on an upstream
// login for the identity, clearing it when hostedDomain is empty. Called on
// every successful upstream login so access policies evaluated later (session
// reuse, device approval, refresh) see the IdP's latest answer.
func (s *Storage) SetIdentityHostedDomain(ctx context.Context, provider, providerUserID, hostedDomain string) error {
	if s.keys == nil {
		return ErrEncryptionNotConfigured
	}
	return storeq.New(s.db).SetIdentityHostedDomain(ctx, storeq.SetIdentityHostedDomainParams{
		HostedDomain:    nullableString(hostedDomain),
		Provider:        provider,
		ProviderSubHash: sql.NullString{String: s.keys.ProviderSubHash(provider, providerUserID), Valid: true},
	})
}

func nullableString(v string) sql.NullString {
	return sql.NullString{String: v, Valid: v != ""}
}

func (s *Storage) getUserByID(ctx context.Context, tx *sql.Tx, userID string) (*User, error) {
	row, err := storeq.New(tx).GetUserForTxByID(ctx, userID)
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
	user := buildCoreUser(row.ID, email, row.EmailVerified, name, row.Status)
	user.HostedDomain = row.HostedDomain
	return user, nil
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
	email, name, err := s.pii().resolveUser(row.ID, row.EmailCiphertext, row.EmailNonce, row.EmailEncKeyID, row.EmailEncVersion, row.NameCiphertext, row.NameNonce, row.NameEncKeyID, row.NameEncVersion)
	if err != nil {
		return nil, err
	}
	user := buildFullUser(row.ID, email, row.EmailVerified, name, row.Status, row.CreatedAt, row.UpdatedAt)
	user.HostedDomain = row.HostedDomain
	return user, nil
}

func (s *Storage) setUserinfo(ctx context.Context, userinfo *oidc.UserInfo, userID string, scopes []string) error {
	row, err := storeq.New(s.db).GetUserInfoFieldsByID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	email, name, err := s.pii().resolveUser(row.ID, row.EmailCiphertext, row.EmailNonce, row.EmailEncKeyID, row.EmailEncVersion, row.NameCiphertext, row.NameNonce, row.NameEncKeyID, row.NameEncVersion)
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
