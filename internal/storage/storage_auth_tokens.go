package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/storage/storeq"
)

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
