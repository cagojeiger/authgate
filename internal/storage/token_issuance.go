package storage

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

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
			return "", "", time.Time{}, errRefreshGrantRefused()
		}
	}

	var currentRefreshHash string
	var parentID uuid.NullUUID
	graceChild := false
	if currentRefreshToken != "" {
		currentRefreshHash = s.keys.RefreshHash(currentRefreshToken)
		// A redeemed token that already has a child is being redeemed again
		// under the reuse grace. Decide it here, holding the redeemed row's lock
		// until the new child commits, so concurrent grace requests are counted
		// one after another and the cap holds.
		graceRequested := false
		if m, ok := request.(*RefreshTokenModel); ok {
			graceRequested = m.graceRedemption
		}
		var parent string
		parent, graceChild, err = s.lockAndCheckGraceChild(ctx, tx, qtx, currentRefreshHash, graceRequested, now)
		if err != nil {
			return "", "", time.Time{}, err
		}
		if parent != "" {
			id, perr := uuid.Parse(parent)
			if perr != nil {
				return "", "", time.Time{}, perr
			}
			parentID = uuid.NullUUID{UUID: id, Valid: true}
		}
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
		ParentID:  parentID,
	})
	if err != nil {
		return "", "", time.Time{}, err
	}

	if err = tx.Commit(); err != nil {
		return "", "", time.Time{}, err
	}
	if graceChild {
		s.auditRefreshReuseGrace(ctx, derived.userID, derived.familyID, "issued")
	}

	// A successful refresh grant is deliberately not audited. It is the highest
	// volume event by far and records nothing the system does not already hold:
	// refresh_tokens.used_at carries last-use per credential, auth.login carries
	// the authentication event, and replay, revocation and status changes are
	// each audited on their own. Logging every routine rotation would dominate
	// the audit log while adding no detection capability.

	return tokenID, newRefresh, expiration, nil
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
