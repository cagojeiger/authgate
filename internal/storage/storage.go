package storage

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/storage/storeq"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrEmailConflict = errors.New("email_conflict")
)

// StateChecker validates that a user is still eligible for token issuance.
// It is applied on both authorization_code and refresh_token grant lookups.
// Injected from main.go — storage never imports service or guard packages.
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
	clients         sync.Map // map[string]*ClientModel (client_id → client)
	cimdFetcher     CIMDFetcher
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

// DB returns the underlying *sql.DB. For testing only.
func (s *Storage) DB() *sql.DB { return s.db }

// hashToken returns SHA-256 hex hash of a token string.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// --- op.Storage: AuthStorage ---

func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	resource := ResourceFromContext(ctx)
	if resource == "" {
		client, err := s.GetClientByClientID(ctx, req.ClientID)
		if err == nil {
			if cm, ok := client.(*ClientModel); ok && cm.LoginChannel == "mcp" {
				return nil, &oidc.Error{ErrorType: "invalid_target", Description: "missing resource"}
			}
		}
	}

	ar := &AuthRequestModel{
		ID:                  s.idgen.NewUUID(),
		ClientID:            req.ClientID,
		Resource:            resource,
		RedirectURI:         req.RedirectURI,
		Scopes:              StringArray(req.Scopes),
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: string(req.CodeChallengeMethod),
		ExpiresAt:           s.clock.Now().Add(10 * time.Minute),
		CreatedAt:           s.clock.Now(),
	}

	err := storeq.New(s.db).InsertAuthRequest(ctx, storeq.InsertAuthRequestParams{
		ID:                  ar.ID,
		ClientID:            ar.ClientID,
		Resource:            sql.NullString{String: ar.Resource, Valid: true},
		RedirectUri:         ar.RedirectURI,
		Scopes:              []string(ar.Scopes),
		State:               sql.NullString{String: ar.State, Valid: true},
		Nonce:               sql.NullString{String: ar.Nonce, Valid: true},
		CodeChallenge:       sql.NullString{String: ar.CodeChallenge, Valid: true},
		CodeChallengeMethod: sql.NullString{String: ar.CodeChallengeMethod, Valid: true},
		ExpiresAt:           ar.ExpiresAt,
		CreatedAt:           ar.CreatedAt,
	})
	return ar, err
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	row, err := storeq.New(s.db).GetAuthRequestByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ar := authRequestModelFromRowByID(row)
	if s.clock.Now().After(ar.ExpiresAt) {
		return nil, &oidc.Error{ErrorType: "invalid_request", Description: "auth request expired"}
	}
	return ar, nil
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	row, err := storeq.New(s.db).GetAuthRequestByCode(ctx, code)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ar := authRequestModelFromRowByCode(row)
	if s.clock.Now().After(ar.ExpiresAt) {
		return nil, &oidc.Error{ErrorType: "invalid_grant", Description: "authorization code expired"}
	}
	requestResource := ResourceFromContext(ctx)
	if ar.Resource != "" {
		if requestResource == "" {
			return nil, &oidc.Error{ErrorType: "invalid_target", Description: "missing resource"}
		}
		if requestResource != ar.Resource {
			return nil, &oidc.Error{ErrorType: "invalid_target", Description: "resource mismatch"}
		}
	} else if requestResource != "" {
		return nil, &oidc.Error{ErrorType: "invalid_target", Description: "unexpected resource"}
	}
	if s.stateChecker != nil && ar.Subject != nil && *ar.Subject != "" {
		user, err := s.GetUserByID(ctx, *ar.Subject)
		if err != nil {
			return nil, &oidc.Error{ErrorType: "invalid_grant", Description: "subject lookup failed"}
		}
		if err := s.stateChecker(user); err != nil {
			return nil, &oidc.Error{ErrorType: "invalid_grant", Description: err.Error()}
		}
	}
	return ar, err
}

func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	return storeq.New(s.db).UpdateAuthRequestCode(ctx, storeq.UpdateAuthRequestCodeParams{
		Code: sql.NullString{String: code, Valid: true},
		ID:   id,
	})
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return storeq.New(s.db).DeleteAuthRequestByID(ctx, id)
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
	qtx := storeq.New(tx)

	// Determine family_id, user_id, client_id, scopes from request
	familyID := s.idgen.NewUUID()
	userID := request.GetSubject()
	clientID := ""
	resource := ""
	var scopes []string

	if ar, ok := request.(*AuthRequestModel); ok {
		clientID = ar.GetClientID()
		resource = ar.Resource
		scopes = ar.GetScopes()
	} else if rtr, ok := request.(op.RefreshTokenRequest); ok {
		clientID = rtr.GetClientID()
		scopes = rtr.GetScopes()
		if existing, ok := request.(*RefreshTokenModel); ok {
			resource = existing.Resource
		}
		// Read family_id BEFORE revoking old token to preserve the chain
		if currentRefreshToken != "" {
			oldHash := hashToken(currentRefreshToken)
			fid, err := qtx.GetRefreshFamilyIDByTokenHash(ctx, oldHash)
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
		_, err = qtx.RevokeRefreshTokenByHash(ctx, storeq.RevokeRefreshTokenByHashParams{
			RevokedAt: sql.NullTime{Time: now, Valid: true},
			TokenHash: oldHash,
		})
		if err != nil {
			return "", "", time.Time{}, err
		}
	}

	err = qtx.InsertRefreshToken(ctx, storeq.InsertRefreshTokenParams{
		ID:        s.idgen.NewUUID(),
		TokenHash: newHash,
		FamilyID:  familyID,
		UserID:    userID,
		ClientID:  clientID,
		Resource:  sql.NullString{String: resource, Valid: true},
		Scopes:    scopes,
		ExpiresAt: now.Add(s.refreshTokenTTL),
		CreatedAt: now,
	})
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
	qtx := storeq.New(tx)

	row, err := qtx.GetRefreshTokenForUpdateByHash(ctx, h)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, op.ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, err
	}
	rt := RefreshTokenModel{
		ID:        row.ID,
		TokenHash: row.TokenHash,
		FamilyID:  row.FamilyID,
		UserID:    row.UserID,
		ClientID:  row.ClientID,
		Resource:  row.Resource,
		Scopes:    StringArray(row.Scopes),
		ExpiresAt: row.ExpiresAt,
		RevokedAt: nullTimePtr(row.RevokedAt),
		UsedAt:    nullTimePtr(row.UsedAt),
	}

	// Already used/revoked → reuse detection → family revoke
	if rt.RevokedAt != nil || rt.UsedAt != nil {
		revokeErr := qtx.RevokeRefreshFamily(ctx, storeq.RevokeRefreshFamilyParams{
			RevokedAt: sql.NullTime{Time: now, Valid: true},
			FamilyID:  rt.FamilyID,
		})
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
	requestResource := ResourceFromContext(ctx)
	if rt.Resource != "" {
		if requestResource == "" {
			tx.Commit()
			return nil, &oidc.Error{ErrorType: "invalid_target", Description: "missing resource"}
		}
		if requestResource != rt.Resource {
			tx.Commit()
			return nil, &oidc.Error{ErrorType: "invalid_target", Description: "resource mismatch"}
		}
	} else if requestResource != "" {
		tx.Commit()
		return nil, &oidc.Error{ErrorType: "invalid_target", Description: "unexpected resource"}
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
	err = qtx.MarkRefreshTokenUsedAndRevokedByID(ctx, storeq.MarkRefreshTokenUsedAndRevokedByIDParams{
		UsedAt: sql.NullTime{Time: now, Valid: true},
		ID:     rt.ID,
	})
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &rt, nil
}

func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	return storeq.New(s.db).RevokeSessionsByUserID(ctx, storeq.RevokeSessionsByUserIDParams{
		RevokedAt: sql.NullTime{Time: s.clock.Now(), Valid: true},
		UserID:    userID,
	})
}

func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	now := s.clock.Now()
	q := storeq.New(s.db)

	// Try as raw token (hash it) first
	h := hashToken(tokenOrTokenID)
	rows, _ := q.RevokeRefreshTokenByHash(ctx, storeq.RevokeRefreshTokenByHashParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		TokenHash: h,
	})
	if rows > 0 {
		return nil
	}

	// Try as token ID (UUID) directly
	_ = q.RevokeRefreshTokenByIDText(ctx, storeq.RevokeRefreshTokenByIDTextParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		ID:        tokenOrTokenID,
	})

	// RFC 7009: always return 200 regardless of whether anything was revoked
	return nil
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	h := hashToken(token)
	row, err := storeq.New(s.db).GetRefreshTokenInfoByHashAndClientID(ctx, storeq.GetRefreshTokenInfoByHashAndClientIDParams{
		TokenHash: h,
		ClientID:  clientID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", op.ErrInvalidRefreshToken
	}
	if err != nil {
		return "", "", err
	}
	return row.UserID, row.ID, nil
}

func nullTimePtr(v sql.NullTime) *time.Time {
	if !v.Valid {
		return nil
	}
	t := v.Time
	return &t
}

func authRequestModelFromRowByID(row storeq.GetAuthRequestByIDRow) *AuthRequestModel {
	return &AuthRequestModel{
		ID:                  row.ID,
		ClientID:            row.ClientID,
		Resource:            row.Resource,
		RedirectURI:         row.RedirectUri,
		Scopes:              StringArray(row.Scopes),
		State:               row.State,
		Nonce:               row.Nonce,
		CodeChallenge:       row.CodeChallenge,
		CodeChallengeMethod: row.CodeChallengeMethod,
		Subject:             nullStringToPtr(row.Subject),
		AuthTime:            nullTimePtr(row.AuthTime),
		IsDone:              row.Done,
		Code:                nullStringToPtr(row.Code),
		ExpiresAt:           row.ExpiresAt,
		CreatedAt:           row.CreatedAt,
	}
}

func authRequestModelFromRowByCode(row storeq.GetAuthRequestByCodeRow) *AuthRequestModel {
	return &AuthRequestModel{
		ID:                  row.ID,
		ClientID:            row.ClientID,
		Resource:            row.Resource,
		RedirectURI:         row.RedirectUri,
		Scopes:              StringArray(row.Scopes),
		State:               row.State,
		Nonce:               row.Nonce,
		CodeChallenge:       row.CodeChallenge,
		CodeChallengeMethod: row.CodeChallengeMethod,
		Subject:             nullStringToPtr(row.Subject),
		AuthTime:            nullTimePtr(row.AuthTime),
		IsDone:              row.Done,
		Code:                nullStringToPtr(row.Code),
		ExpiresAt:           row.ExpiresAt,
		CreatedAt:           row.CreatedAt,
	}
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
	// 1. YAML 클라이언트: 메모리 조회
	if v, ok := s.clients.Load(clientID); ok {
		return v.(*ClientModel), nil
	}
	// 2. CIMD 클라이언트: URL 형식이면 fetch
	if s.cimdFetcher != nil && isCIMDClientID(clientID) {
		return s.cimdFetcher.FetchClient(ctx, clientID)
	}
	return nil, ErrNotFound
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	v, ok := s.clients.Load(clientID)
	if !ok {
		if s.cimdFetcher != nil && isCIMDClientID(clientID) {
			client, err := s.cimdFetcher.FetchClient(ctx, clientID)
			if err != nil {
				return ErrNotFound
			}
			cm := client
			if cm.SecretHash == nil {
				return errors.New("public client cannot use client_secret")
			}
			return verifyBcrypt(*cm.SecretHash, clientSecret)
		}
		return ErrNotFound
	}
	c := v.(*ClientModel)
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
	return storeq.New(s.db).InsertDeviceCode(ctx, storeq.InsertDeviceCodeParams{
		ID:         s.idgen.NewUUID(),
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scopes:     scopes,
		ExpiresAt:  expires,
		CreatedAt:  s.clock.Now(),
	})
}

func (s *Storage) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	qtx := storeq.New(tx)

	row, err := qtx.GetDeviceAuthorizationForUpdate(ctx, storeq.GetDeviceAuthorizationForUpdateParams{
		DeviceCode: deviceCode,
		ClientID:   clientID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	dc := &DeviceCodeModel{
		ID:        row.ID,
		ClientID:  row.ClientID,
		Scopes:    StringArray(row.Scopes),
		State:     row.State,
		Subject:   nullStringToPtr(row.Subject),
		ExpiresAt: row.ExpiresAt,
		AuthTime:  nullTimePtr(row.AuthTime),
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
		err = qtx.UpdateDeviceCodeStateConsumedByID(ctx, dc.ID)
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
		return nil, &oidc.Error{ErrorType: "invalid_grant", Description: "device code already consumed"}
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
	row, err := storeq.New(s.db).GetDeviceCodeByUserCode(ctx, userCode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &DeviceCodeModel{
		ID:         row.ID,
		DeviceCode: row.DeviceCode,
		UserCode:   row.UserCode,
		ClientID:   row.ClientID,
		Scopes:     StringArray(row.Scopes),
		State:      row.State,
		Subject:    nullStringToPtr(row.Subject),
		ExpiresAt:  row.ExpiresAt,
		AuthTime:   nullTimePtr(row.AuthTime),
	}, nil
}

// ApproveDeviceCode sets a device code to approved state with subject and auth_time.
func (s *Storage) ApproveDeviceCode(ctx context.Context, userCode, subject string) error {
	now := s.clock.Now()
	rows, err := storeq.New(s.db).ApproveDeviceCodeByUserCode(ctx, storeq.ApproveDeviceCodeByUserCodeParams{
		Subject:  sql.NullString{String: subject, Valid: true},
		AuthTime: sql.NullTime{Time: now, Valid: true},
		UserCode: userCode,
	})
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("device code not found, expired, or already processed")
	}
	return nil
}

// DenyDeviceCode sets a device code to denied state.
func (s *Storage) DenyDeviceCode(ctx context.Context, userCode string) error {
	return storeq.New(s.db).DenyDeviceCodeByUserCode(ctx, userCode)
}

// Compile-time interface checks
var (
	_ op.Storage                    = (*Storage)(nil)
	_ op.DeviceAuthorizationStorage = (*Storage)(nil)
)
