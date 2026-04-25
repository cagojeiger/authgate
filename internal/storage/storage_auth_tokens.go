package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// --- op.Storage: AuthStorage ---

func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	if req.CodeChallenge == "" {
		err := oidc.ErrInvalidRequest()
		err.Description = "PKCE S256 required"
		return nil, err
	}
	if req.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
		err := oidc.ErrInvalidRequest()
		err.Description = "PKCE S256 required"
		return nil, err
	}

	resource := ResourceFromContext(ctx)
	if resource == "" {
		client, err := s.resolveClient(ctx, req.ClientID)
		if err == nil {
			if err := s.resourcePolicy.ValidateAuthorizeRequest(ctx, client, resource); err != nil {
				return nil, err
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
	row, err := storeq.New(s.db).GetAuthRequestByCode(ctx, sql.NullString{String: code, Valid: true})
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
	if err := s.resourcePolicy.ValidateTokenRequest(ctx, ar.ClientID, ar.Resource, requestResource); err != nil {
		return nil, err
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

	derived, err := s.deriveRefreshTokenAttributes(ctx, qtx, request, currentRefreshToken)
	if err != nil {
		return "", "", time.Time{}, err
	}

	if err := revokeRefreshTokenIfPresent(ctx, qtx, currentRefreshToken, now); err != nil {
		return "", "", time.Time{}, err
	}

	err = qtx.InsertRefreshToken(ctx, storeq.InsertRefreshTokenParams{
		ID:        s.idgen.NewUUID(),
		TokenHash: newHash,
		FamilyID:  derived.familyID,
		UserID:    derived.userID,
		ClientID:  derived.clientID,
		Resource:  sql.NullString{String: derived.resource, Valid: true},
		Scopes:    derived.scopes,
		ExpiresAt: now.Add(s.refreshTokenTTL),
		CreatedAt: now,
	})
	if err != nil {
		return "", "", time.Time{}, err
	}

	if err = tx.Commit(); err != nil {
		return "", "", time.Time{}, err
	}

	// Audit token.refresh only when this is a refresh-token grant (not the initial code exchange).
	if currentRefreshToken != "" {
		s.AuditLog(ctx, &derived.userID, EventTokenRefresh, "", "", map[string]any{
			"client_id": derived.clientID,
			"family_id": derived.familyID,
		})
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

	rt, err := loadRefreshTokenForUpdate(ctx, qtx, h)
	if err != nil {
		return nil, err
	}

	// Already used/revoked → reuse detection → family revoke
	if isRefreshTokenUsedOrRevoked(rt) {
		if err := revokeRefreshFamilyOnReuse(ctx, qtx, rt.FamilyID, now); err != nil {
			return nil, op.ErrInvalidRefreshToken
		}
		if err := tx.Commit(); err != nil {
			return nil, op.ErrInvalidRefreshToken
		}
		// Audit only after successful commit
		s.auditRefreshReuseDetection(ctx, rt.UserID, rt.FamilyID)
		return nil, op.ErrInvalidRefreshToken
	}

	if err := s.validateRefreshTokenRequest(ctx, tx, rt, now); err != nil {
		return nil, err
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
	return rt, nil
}

func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	err := storeq.New(s.db).RevokeSessionsByUserID(ctx, storeq.RevokeSessionsByUserIDParams{
		RevokedAt: sql.NullTime{Time: s.clock.Now(), Valid: true},
		UserID:    userID,
	})
	if err != nil {
		return err
	}
	s.AuditLog(ctx, &userID, EventAuthLogout, "", "", nil)
	return nil
}

func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	now := s.clock.Now()
	q := storeq.New(s.db)

	if tryRevokeRefreshByHash(ctx, q, tokenOrTokenID, now) {
		s.AuditLog(ctx, &userID, EventAuthTokenRevoked, "", "", map[string]any{"client_id": clientID})
		return nil
	}

	if tryRevokeRefreshByIDReturning(ctx, q, tokenOrTokenID, now) {
		s.AuditLog(ctx, &userID, EventAuthTokenRevoked, "", "", map[string]any{"client_id": clientID})
	}

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

type refreshTokenAttributes struct {
	familyID string
	userID   string
	clientID string
	resource string
	scopes   []string
}

func (s *Storage) deriveRefreshTokenAttributes(ctx context.Context, qtx *storeq.Queries, request op.TokenRequest, currentRefreshToken string) (refreshTokenAttributes, error) {
	derived := refreshTokenAttributes{
		familyID: s.idgen.NewUUID(),
		userID:   request.GetSubject(),
	}

	if ar, ok := request.(*AuthRequestModel); ok {
		derived.clientID = ar.GetClientID()
		derived.resource = ar.Resource
		derived.scopes = ar.GetScopes()
		return derived, nil
	}

	if rtr, ok := request.(op.RefreshTokenRequest); ok {
		derived.clientID = rtr.GetClientID()
		derived.scopes = rtr.GetScopes()
		if existing, ok := request.(*RefreshTokenModel); ok {
			derived.resource = existing.Resource
		}
		if currentRefreshToken != "" {
			oldHash := hashToken(currentRefreshToken)
			fid, err := qtx.GetRefreshFamilyIDByTokenHash(ctx, oldHash)
			if err == nil {
				derived.familyID = fid
			}
		}
		return derived, nil
	}

	if das, ok := request.(*op.DeviceAuthorizationState); ok {
		derived.clientID = das.ClientID
		derived.scopes = das.Scopes
	}
	return derived, nil
}

func revokeRefreshTokenIfPresent(ctx context.Context, qtx *storeq.Queries, currentRefreshToken string, now time.Time) error {
	if currentRefreshToken == "" {
		return nil
	}

	oldHash := hashToken(currentRefreshToken)
	_, err := qtx.RevokeRefreshTokenByHash(ctx, storeq.RevokeRefreshTokenByHashParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		TokenHash: oldHash,
	})
	return err
}

func loadRefreshTokenForUpdate(ctx context.Context, qtx *storeq.Queries, tokenHash string) (*RefreshTokenModel, error) {
	row, err := qtx.GetRefreshTokenForUpdateByHash(ctx, tokenHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, op.ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, err
	}

	return &RefreshTokenModel{
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
	}, nil
}

func isRefreshTokenUsedOrRevoked(rt *RefreshTokenModel) bool {
	return rt.RevokedAt != nil || rt.UsedAt != nil
}

func revokeRefreshFamilyOnReuse(ctx context.Context, qtx *storeq.Queries, familyID string, now time.Time) error {
	return qtx.RevokeRefreshFamily(ctx, storeq.RevokeRefreshFamilyParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		FamilyID:  familyID,
	})
}

func (s *Storage) auditRefreshReuseDetection(ctx context.Context, userID, familyID string) {
	s.AuditLog(ctx, &userID, "auth.refresh_reuse_detected", "", "", map[string]any{"family_id": familyID})
	s.AuditLog(ctx, &userID, "auth.refresh_family_revoked", "", "", map[string]any{"family_id": familyID})
}

func (s *Storage) validateRefreshTokenRequest(ctx context.Context, tx *sql.Tx, rt *RefreshTokenModel, now time.Time) error {
	if now.After(rt.ExpiresAt) {
		return op.ErrInvalidRefreshToken
	}

	requestResource := ResourceFromContext(ctx)
	if err := s.resourcePolicy.ValidateTokenRequest(ctx, rt.ClientID, rt.Resource, requestResource); err != nil {
		return err
	}

	if s.stateChecker != nil {
		user, err := s.getUserByID(ctx, tx, rt.UserID)
		if err != nil {
			return op.ErrInvalidRefreshToken
		}
		if err := s.stateChecker(user); err != nil {
			return &oidc.Error{ErrorType: "invalid_grant", Description: err.Error()}
		}
	}
	return nil
}

func tryRevokeRefreshByHash(ctx context.Context, q *storeq.Queries, tokenOrTokenID string, now time.Time) bool {
	h := hashToken(tokenOrTokenID)
	rows, _ := q.RevokeRefreshTokenByHash(ctx, storeq.RevokeRefreshTokenByHashParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		TokenHash: h,
	})
	return rows > 0
}

// tryRevokeRefreshByIDReturning attempts to revoke a refresh token by UUID ID and returns true if a row was affected.
func tryRevokeRefreshByIDReturning(ctx context.Context, q *storeq.Queries, tokenOrTokenID string, now time.Time) bool {
	if _, err := uuid.Parse(tokenOrTokenID); err != nil {
		return false
	}
	rows, err := q.RevokeRefreshTokenByID(ctx, storeq.RevokeRefreshTokenByIDParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		ID:        tokenOrTokenID,
	})
	if err != nil {
		return false
	}
	return rows > 0
}

// GetAuthRequestModel fetches the auth request by ID and returns the concrete model.
// It does not apply resource policy or state checks — callers use this for pre-completion validation.
func (s *Storage) GetAuthRequestModel(ctx context.Context, id string) (*AuthRequestModel, error) {
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
