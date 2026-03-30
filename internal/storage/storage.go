package storage

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrEmailConflict = errors.New("email_conflict")
)

// StateChecker validates user state for refresh grants.
// Injected from main.go using guard.DeriveLoginState — storage never imports guard.
type StateChecker func(user *User) error

type Storage struct {
	db              *sql.DB
	clock           clock.Clock
	idgen           idgen.IDGenerator
	stateChecker    StateChecker
	signingKey      *rsa.PrivateKey
	signingKeyID    string
	previousKey     *rsa.PrivateKey
	previousKeyID   string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

func New(db *sql.DB, clk clock.Clock, gen idgen.IDGenerator, checker StateChecker, accessTTL, refreshTTL time.Duration) *Storage {
	return &Storage{
		db:              db,
		clock:           clk,
		idgen:           gen,
		stateChecker:    checker,
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
	}
}

// SetSigningKey sets the current RSA signing key used for JWT issuance.
func (s *Storage) SetSigningKey(key *rsa.PrivateKey, keyID string) {
	s.signingKey = key
	s.signingKeyID = keyID
}

// SetPreviousKey sets the previous signing key for 2-slot rotation.
// JWKS will return both keys; JWTs are signed with the current key only.
func (s *Storage) SetPreviousKey(key *rsa.PrivateKey, keyID string) {
	s.previousKey = key
	s.previousKeyID = keyID
}

// hashToken returns SHA-256 hex hash of a token string.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// --- op.Storage: AuthStorage ---

func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	ar := &AuthRequestModel{
		ID:                  s.idgen.NewUUID(),
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scopes:              StringArray(req.Scopes),
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: string(req.CodeChallengeMethod),
		ExpiresAt:           s.clock.Now().Add(10 * time.Minute),
		CreatedAt:           s.clock.Now(),
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_requests (id, client_id, redirect_uri, scopes, state, nonce, code_challenge, code_challenge_method, expires_at, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		ar.ID, ar.ClientID, ar.RedirectURI, ar.Scopes, ar.State, ar.Nonce,
		ar.CodeChallenge, ar.CodeChallengeMethod, ar.ExpiresAt, ar.CreatedAt,
	)
	return ar, err
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	ar := &AuthRequestModel{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, client_id, redirect_uri, scopes, state, nonce, code_challenge, code_challenge_method,
		        subject, auth_time, done, code, expires_at, created_at
		 FROM auth_requests WHERE id = $1`, id,
	).Scan(&ar.ID, &ar.ClientID, &ar.RedirectURI, &ar.Scopes, &ar.State, &ar.Nonce,
		&ar.CodeChallenge, &ar.CodeChallengeMethod,
		&ar.Subject, &ar.AuthTime, &ar.IsDone, &ar.Code, &ar.ExpiresAt, &ar.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return ar, err
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	ar := &AuthRequestModel{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, client_id, redirect_uri, scopes, state, nonce, code_challenge, code_challenge_method,
		        subject, auth_time, done, code, expires_at, created_at
		 FROM auth_requests WHERE code = $1`, code,
	).Scan(&ar.ID, &ar.ClientID, &ar.RedirectURI, &ar.Scopes, &ar.State, &ar.Nonce,
		&ar.CodeChallenge, &ar.CodeChallengeMethod,
		&ar.Subject, &ar.AuthTime, &ar.IsDone, &ar.Code, &ar.ExpiresAt, &ar.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return ar, err
}

func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE auth_requests SET code = $1 WHERE id = $2`, code, id)
	return err
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM auth_requests WHERE id = $1`, id)
	return err
}

func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	tokenID := s.idgen.NewUUID()
	expiration := s.clock.Now().Add(s.accessTokenTTL)
	return tokenID, expiration, nil
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	tokenID := s.idgen.NewUUID()
	expiration := s.clock.Now().Add(s.accessTokenTTL)

	newRefresh, err := s.idgen.NewOpaqueToken()
	if err != nil {
		return "", "", time.Time{}, err
	}

	newHash := hashToken(newRefresh)
	now := s.clock.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", time.Time{}, err
	}
	defer tx.Rollback()

	// Determine family_id, user_id, client_id, scopes from request
	familyID := s.idgen.NewUUID()
	userID := request.GetSubject()
	clientID := ""
	var scopes []string

	if ar, ok := request.(*AuthRequestModel); ok {
		clientID = ar.GetClientID()
		scopes = ar.GetScopes()
	} else if rtr, ok := request.(op.RefreshTokenRequest); ok {
		clientID = rtr.GetClientID()
		scopes = rtr.GetScopes()
		// Read family_id BEFORE revoking old token to preserve the chain
		if currentRefreshToken != "" {
			oldHash := hashToken(currentRefreshToken)
			var fid string
			err = tx.QueryRowContext(ctx, `SELECT family_id FROM refresh_tokens WHERE token_hash = $1`, oldHash).Scan(&fid)
			if err == nil {
				familyID = fid
			}
		}
	} else if das, ok := request.(*op.DeviceAuthorizationState); ok {
		clientID = das.ClientID
		scopes = das.Scopes
	}

	// Revoke old refresh token AFTER reading family_id
	if currentRefreshToken != "" {
		oldHash := hashToken(currentRefreshToken)
		_, err = tx.ExecContext(ctx,
			`UPDATE refresh_tokens SET revoked_at = $1, used_at = $1 WHERE token_hash = $2 AND revoked_at IS NULL`,
			now, oldHash)
		if err != nil {
			return "", "", time.Time{}, err
		}
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		s.idgen.NewUUID(), newHash, familyID, userID, clientID, StringArray(scopes),
		now.Add(s.refreshTokenTTL), now,
	)
	if err != nil {
		return "", "", time.Time{}, err
	}

	if err = tx.Commit(); err != nil {
		return "", "", time.Time{}, err
	}

	return tokenID, newRefresh, expiration, nil
}

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	h := hashToken(refreshToken)
	now := s.clock.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var rt RefreshTokenModel
	err = tx.QueryRowContext(ctx,
		`SELECT id, token_hash, family_id, user_id, client_id, scopes, expires_at, revoked_at, used_at
		 FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`, h,
	).Scan(&rt.ID, &rt.TokenHash, &rt.FamilyID, &rt.UserID, &rt.ClientID, &rt.Scopes,
		&rt.ExpiresAt, &rt.RevokedAt, &rt.UsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, op.ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, err
	}

	// Already used/revoked → reuse detection → family revoke
	if rt.RevokedAt != nil || rt.UsedAt != nil {
		_, revokeErr := tx.ExecContext(ctx,
			`UPDATE refresh_tokens SET revoked_at = $1 WHERE family_id = $2 AND revoked_at IS NULL`,
			now, rt.FamilyID)
		if revokeErr != nil {
			return nil, op.ErrInvalidRefreshToken
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return nil, op.ErrInvalidRefreshToken
		}
		// Audit only after successful commit
		s.AuditLog(ctx, &rt.UserID, "auth.refresh_reuse_detected", "", "", map[string]any{"family_id": rt.FamilyID})
		s.AuditLog(ctx, &rt.UserID, "auth.refresh_family_revoked", "", "", map[string]any{"family_id": rt.FamilyID})
		return nil, op.ErrInvalidRefreshToken
	}

	// Expired
	if now.After(rt.ExpiresAt) {
		tx.Commit()
		return nil, op.ErrInvalidRefreshToken
	}

	// State check (DeriveLoginState via injected function)
	if s.stateChecker != nil {
		user, err := s.getUserByID(ctx, tx, rt.UserID)
		if err != nil {
			tx.Commit()
			return nil, op.ErrInvalidRefreshToken
		}
		if err := s.stateChecker(user); err != nil {
			tx.Commit()
			return nil, &oidc.Error{ErrorType: "invalid_grant", Description: err.Error()}
		}
	}

	// Atomically claim the token within the FOR UPDATE transaction.
	// This prevents race conditions: a concurrent request will see used_at != nil
	// and trigger family revoke (reuse detection) above.
	_, err = tx.ExecContext(ctx,
		`UPDATE refresh_tokens SET used_at = $1, revoked_at = $1 WHERE id = $2`, now, rt.ID)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &rt, nil
}

func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL`,
		s.clock.Now(), userID)
	return err
}

func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	now := s.clock.Now()

	// Try as raw token (hash it) first
	h := hashToken(tokenOrTokenID)
	res, _ := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = $1 WHERE token_hash = $2 AND revoked_at IS NULL`,
		now, h)
	if rows, _ := res.RowsAffected(); rows > 0 {
		return nil
	}

	// Try as token ID (UUID) directly
	s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = $1 WHERE id::text = $2 AND revoked_at IS NULL`,
		now, tokenOrTokenID)

	// RFC 7009: always return 200 regardless of whether anything was revoked
	return nil
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	h := hashToken(token)
	var userID, tokenID string
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id, id FROM refresh_tokens WHERE token_hash = $1 AND client_id = $2`, h, clientID,
	).Scan(&userID, &tokenID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", op.ErrInvalidRefreshToken
	}
	return userID, tokenID, err
}

func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	if s.signingKey == nil {
		return nil, errors.New("no signing key configured")
	}
	return &signingKeyModel{
		id:        s.signingKeyID,
		algorithm: jose.RS256,
		key:       s.signingKey,
	}, nil
}

func (s *Storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	if s.signingKey == nil {
		return nil, nil
	}
	keys := []op.Key{
		&publicKeyModel{
			id:        s.signingKeyID,
			algorithm: jose.RS256,
			key:       &s.signingKey.PublicKey,
		},
	}
	// 2-slot rotation: include previous key if set
	if s.previousKey != nil {
		keys = append(keys, &publicKeyModel{
			id:        s.previousKeyID,
			algorithm: jose.RS256,
			key:       &s.previousKey.PublicKey,
		})
	}
	return keys, nil
}

// --- op.Storage: OPStorage ---

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	c := &ClientModel{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, client_id, client_secret_hash, client_type, name, redirect_uris, allowed_scopes, allowed_grant_types
		 FROM oauth_clients WHERE client_id = $1`, clientID,
	).Scan(&c.UUID, &c.ID, &c.SecretHash, &c.Type, &c.Name, &c.RedirectURIList,
		&c.AllowedScopeList, &c.AllowedGrantTypeList)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	c := &ClientModel{}
	err := s.db.QueryRowContext(ctx,
		`SELECT client_secret_hash FROM oauth_clients WHERE client_id = $1`, clientID,
	).Scan(&c.SecretHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if c.SecretHash == nil {
		return errors.New("public client cannot use client_secret")
	}
	return verifyBcrypt(*c.SecretHash, clientSecret)
}

func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return s.setUserinfo(ctx, userinfo, userID, scopes)
}

func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	return s.setUserinfo(ctx, userinfo, subject, []string{"openid", "profile", "email"})
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	var ui oidc.UserInfo
	if err := s.setUserinfo(ctx, &ui, subject, []string{"openid", "profile", "email"}); err != nil {
		return err
	}
	introspection.SetUserInfo(&ui)
	return nil
}

func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	return nil, nil
}

func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, ErrNotFound
}

func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return scopes, nil
}

// --- Health ---

func (s *Storage) Health(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// --- DeviceAuthorizationStorage ---

func (s *Storage) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO device_codes (id, device_code, user_code, client_id, scopes, state, expires_at, created_at)
		 VALUES ($1,$2,$3,$4,$5,'pending',$6,$7)`,
		s.idgen.NewUUID(), deviceCode, userCode, clientID, StringArray(scopes), expires, s.clock.Now(),
	)
	return err
}

func (s *Storage) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var dc DeviceCodeModel
	err = tx.QueryRowContext(ctx,
		`SELECT id, client_id, scopes, state, subject, expires_at, auth_time
		 FROM device_codes WHERE device_code = $1 AND client_id = $2 FOR UPDATE`,
		deviceCode, clientID,
	).Scan(&dc.ID, &dc.ClientID, &dc.Scopes, &dc.State, &dc.Subject, &dc.ExpiresAt, &dc.AuthTime)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	now := s.clock.Now()

	// Expired
	if now.After(dc.ExpiresAt) {
		tx.Commit()
		return &op.DeviceAuthorizationState{Expires: dc.ExpiresAt}, nil
	}

	// Denied
	if dc.State == "denied" {
		tx.Commit()
		return &op.DeviceAuthorizationState{Denied: true, Expires: dc.ExpiresAt}, nil
	}

	// Approved → atomically transition to consumed
	if dc.State == "approved" {
		_, err = tx.ExecContext(ctx,
			`UPDATE device_codes SET state = 'consumed' WHERE id = $1`, dc.ID)
		if err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		subject := ""
		if dc.Subject != nil {
			subject = *dc.Subject
		}
		var authTime time.Time
		if dc.AuthTime != nil {
			authTime = *dc.AuthTime
		}
		return &op.DeviceAuthorizationState{
			ClientID: dc.ClientID,
			Scopes:   dc.Scopes,
			Expires:  dc.ExpiresAt,
			Done:     true,
			Subject:  subject,
			AuthTime: authTime,
		}, nil
	}

	// Consumed → already issued
	if dc.State == "consumed" {
		tx.Commit()
		return nil, errors.New("device code already consumed")
	}

	// Pending
	tx.Commit()
	return &op.DeviceAuthorizationState{
		ClientID: dc.ClientID,
		Scopes:   dc.Scopes,
		Expires:  dc.ExpiresAt,
	}, nil
}

// --- Device code business operations (called by service, not by zitadel) ---

// GetDeviceCodeByUserCode looks up a device code by user_code for the approval page.
func (s *Storage) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCodeModel, error) {
	dc := &DeviceCodeModel{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, device_code, user_code, client_id, scopes, state, subject, expires_at, auth_time
		 FROM device_codes WHERE user_code = $1`, userCode,
	).Scan(&dc.ID, &dc.DeviceCode, &dc.UserCode, &dc.ClientID, &dc.Scopes, &dc.State,
		&dc.Subject, &dc.ExpiresAt, &dc.AuthTime)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return dc, err
}

// ApproveDeviceCode sets a device code to approved state with subject and auth_time.
func (s *Storage) ApproveDeviceCode(ctx context.Context, userCode, subject string) error {
	now := s.clock.Now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE device_codes SET state = 'approved', subject = $1, auth_time = $2
		 WHERE user_code = $3 AND state = 'pending' AND expires_at > $2`,
		subject, now, userCode,
	)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return errors.New("device code not found, expired, or already processed")
	}
	return nil
}

// DenyDeviceCode sets a device code to denied state.
func (s *Storage) DenyDeviceCode(ctx context.Context, userCode string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_codes SET state = 'denied'
		 WHERE user_code = $1 AND state = 'pending'`,
		userCode,
	)
	return err
}

// Compile-time interface checks
var (
	_ op.Storage                      = (*Storage)(nil)
	_ op.DeviceAuthorizationStorage   = (*Storage)(nil)
)
