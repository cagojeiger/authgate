package storage

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/clientinfo"
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
	// #184: validate the channel × resource matrix on every /authorize, not
	// only when resource is empty.
	client, err := s.ResolveClient(ctx, req.ClientID)
	if err == nil {
		if err := s.resourcePolicy.ValidateAuthorizeRequest(ctx, client, resource); err != nil {
			return nil, err
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

	err = storeq.New(s.db).InsertAuthRequest(ctx, storeq.InsertAuthRequestParams{
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
	row, err := storeq.New(s.db).GetAuthRequestByCode(ctx, sql.NullString{String: s.codeAtRest(code), Valid: true})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ar := authRequestModelFromRowByCode(row)
	// Surface the plaintext code the caller supplied, not the stored hash.
	ar.Code = &code
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
		Code: sql.NullString{String: s.codeAtRest(code), Valid: true},
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

	newHash := s.keys.RefreshHash(newRefresh)
	now := s.clock.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", time.Time{}, err
	}
	defer func() { _ = tx.Rollback() }()
	qtx := storeq.New(tx)

	derived, err := s.deriveRefreshTokenAttributes(ctx, qtx, request, currentRefreshToken)
	if err != nil {
		return "", "", time.Time{}, err
	}

	// On rotation, refuse to issue a child into a family that reuse detection
	// has tombstoned. The initial code/device exchange mints a fresh family_id
	// that can never be tombstoned, so the check is skipped there.
	if currentRefreshToken != "" {
		revoked, err := qtx.IsRefreshFamilyRevoked(ctx, derived.familyID)
		if err != nil {
			return "", "", time.Time{}, err
		}
		if revoked {
			return "", "", time.Time{}, op.ErrInvalidRefreshToken
		}
	}

	var currentRefreshHash string
	if currentRefreshToken != "" {
		currentRefreshHash = s.keys.RefreshHash(currentRefreshToken)
	}
	if err := revokeRefreshTokenIfPresent(ctx, qtx, currentRefreshHash, now); err != nil {
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

	// A successful refresh grant is deliberately not audited. It is the highest
	// volume event by far and records nothing the system does not already hold:
	// refresh_tokens.used_at carries last-use per credential, auth.login carries
	// the authentication event, and replay, revocation and status changes are
	// each audited on their own. Logging every routine rotation would dominate
	// the audit log while adding no detection capability.

	return tokenID, newRefresh, expiration, nil
}

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	h := s.keys.RefreshHash(refreshToken)
	now := s.clock.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	qtx := storeq.New(tx)

	rt, err := loadRefreshTokenForUpdate(ctx, qtx, h)
	if err != nil {
		return nil, err
	}

	// Already used/revoked → reuse detection → family revoke + tombstone
	if isRefreshTokenUsedOrRevoked(rt) {
		if err := revokeRefreshFamilyOnReuse(ctx, qtx, rt.FamilyID, now); err != nil {
			return nil, op.ErrInvalidRefreshToken
		}
		// Tombstone the family in the same tx as the revoke. RevokeRefreshFamily
		// only flips existing rows; the tombstone is what CreateAccessAndRefreshTokens
		// checks so a child rotating in just after the revoke is still refused.
		if err := tombstoneRefreshFamilyOnReuse(ctx, qtx, rt.FamilyID, rt.UserID, now); err != nil {
			return nil, op.ErrInvalidRefreshToken
		}
		// Write the reuse-detection audit rows in the SAME transaction too, so the
		// revoke, tombstone and audit evidence commit atomically. If any insert
		// fails the whole tx rolls back; the client's retry triggers reuse
		// detection again (token already used/revoked, so it stays unusable).
		if err := s.auditRefreshReuseDetectionTx(ctx, qtx, rt.UserID, rt.FamilyID); err != nil {
			return nil, op.ErrInvalidRefreshToken
		}
		if err := tx.Commit(); err != nil {
			return nil, op.ErrInvalidRefreshToken
		}
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

// TerminateSession revokes the user's server-side session rows only; per OIDC
// RP-Initiated Logout 1.0 §2 vs RFC 7009 it does NOT revoke refresh tokens (RPs
// must call /oauth/revoke). See docs/spec/005-token-lifecycle.md "Logout vs.
// Revoke".
func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	err := storeq.New(s.db).RevokeSessionsByUserID(ctx, storeq.RevokeSessionsByUserIDParams{
		RevokedAt: sql.NullTime{Time: s.clock.Now(), Valid: true},
		UserID:    userID,
	})
	if err != nil {
		return err
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

func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	now := s.clock.Now()
	q := storeq.New(s.db)
	info := clientinfo.FromContext(ctx)

	if tryRevokeRefreshByHash(ctx, q, s.keys.RefreshHash(tokenOrTokenID), now) {
		s.AuditLog(ctx, &userID, EventAuthTokenRevoked, info.IP, info.UserAgent, map[string]any{
			"client_id":   clientID,
			"client_name": s.auditClientName(ctx, clientID),
		})
		return nil
	}

	if tryRevokeRefreshByIDReturning(ctx, q, tokenOrTokenID, now) {
		s.AuditLog(ctx, &userID, EventAuthTokenRevoked, info.IP, info.UserAgent, map[string]any{
			"client_id":   clientID,
			"client_name": s.auditClientName(ctx, clientID),
		})
	}

	// RFC 7009: always return 200 regardless of whether anything was revoked
	return nil
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	h := s.keys.RefreshHash(token)
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
			oldHash := s.keys.RefreshHash(currentRefreshToken)
			fid, err := qtx.GetRefreshFamilyIDByTokenHash(ctx, oldHash)
			if err == nil {
				derived.familyID = fid
			}
		}
		return derived, nil
	}

	if das, ok := request.(*op.DeviceAuthorizationState); ok {
		derived.clientID = das.ClientID
		derived.resource = ResourceFromContext(ctx)
		derived.scopes = das.Scopes
	}
	return derived, nil
}

// revokeRefreshTokenIfPresent revokes the row matching tokenHash, which the
// caller computes with Keys.RefreshHash (empty string when there is no current
// token). Hashing stays in the *Storage caller so the lookup key never has to
// be threaded into free functions.
func revokeRefreshTokenIfPresent(ctx context.Context, qtx *storeq.Queries, tokenHash string, now time.Time) error {
	if tokenHash == "" {
		return nil
	}

	_, err := qtx.RevokeRefreshTokenByHash(ctx, storeq.RevokeRefreshTokenByHashParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		TokenHash: tokenHash,
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

// tombstoneRefreshFamilyOnReuse records a permanent per-family tombstone so a
// child token cannot be issued into the family later (checked by
// CreateAccessAndRefreshTokens). Idempotent via ON CONFLICT DO NOTHING.
func tombstoneRefreshFamilyOnReuse(ctx context.Context, qtx *storeq.Queries, familyID, userID string, now time.Time) error {
	return qtx.TombstoneRefreshFamily(ctx, storeq.TombstoneRefreshFamilyParams{
		FamilyID:  familyID,
		UserID:    userID,
		Reason:    "reuse_detected",
		RevokedAt: now,
	})
}

// auditRefreshReuseDetectionTx writes the reuse-detection and family-revoked
// audit rows via the supplied transaction queries, so they commit atomically
// with the family revoke. An insert error is returned (not swallowed) so the
// caller can roll back the whole reuse-detection transaction.
func (s *Storage) auditRefreshReuseDetectionTx(ctx context.Context, qtx *storeq.Queries, userID, familyID string) error {
	info := clientinfo.FromContext(ctx)
	if err := s.writeAuditLogTx(ctx, qtx, &userID, EventAuthRefreshReuseDetected, info.IP, info.UserAgent, map[string]any{"family_id": familyID}); err != nil {
		return err
	}
	return s.writeAuditLogTx(ctx, qtx, &userID, EventAuthRefreshFamilyRevoked, info.IP, info.UserAgent, map[string]any{"family_id": familyID})
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

// tryRevokeRefreshByHash revokes the row matching tokenHash (computed by the
// caller with Keys.RefreshHash) and reports whether a row was affected.
func tryRevokeRefreshByHash(ctx context.Context, q *storeq.Queries, tokenHash string, now time.Time) bool {
	rows, err := q.RevokeRefreshTokenByHash(ctx, storeq.RevokeRefreshTokenByHashParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		TokenHash: tokenHash,
	})
	if err != nil {
		slog.ErrorContext(ctx, "revoke refresh token by hash", "error", err)
		return false
	}
	return rows > 0
}

// tryRevokeRefreshByIDReturning attempts to revoke a refresh token by UUID ID and returns true if a row was affected.
func tryRevokeRefreshByIDReturning(ctx context.Context, q *storeq.Queries, tokenOrTokenID string, now time.Time) bool {
	if _, err := uuid.Parse(tokenOrTokenID); err != nil {
		return false
	}
	err := q.RevokeRefreshTokenByID(ctx, storeq.RevokeRefreshTokenByIDParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		ID:        tokenOrTokenID,
	})
	if err != nil {
		slog.ErrorContext(ctx, "revoke refresh token by id", "error", err)
		return false
	}
	return true
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
