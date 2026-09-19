package storage

import (
	"context"
	"database/sql"
	"errors"
	"slices"

	"github.com/kangheeyong/authgate/internal/db/storeq"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// consumeRefreshToken owns the final decision after provider validation. Every
// rotation and explicit/replay revocation takes family -> row locks. On replay it
// commits the security revocation (no new grant) before returning invalid_grant.
func (s *Storage) consumeRefreshToken(ctx context.Context, tx *sql.Tx, q *storeq.Queries, request op.TokenRequest, token string) (refreshTokenAttributes, string, bool, error) {
	var empty refreshTokenAttributes
	hash := s.keys.RefreshHash(token)
	family, err := q.GetRefreshFamilyIDByTokenHash(ctx, hash)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, "", false, errRefreshGrantRefused()
	}
	if err != nil {
		return empty, "", false, err
	}
	if err := q.LockRefreshFamily(ctx, family); err != nil {
		return empty, "", false, err
	}
	rt, err := loadRefreshTokenForUpdate(ctx, q, hash)
	if errors.Is(err, op.ErrInvalidRefreshToken) {
		return empty, "", false, errRefreshGrantRefused()
	}
	if err != nil {
		return empty, "", false, err
	}
	r, ok := request.(op.RefreshTokenRequest)
	if !ok || r.GetClientID() != rt.ClientID || r.GetSubject() != rt.UserID {
		return empty, "", false, errRefreshGrantRefused()
	}
	for _, scope := range r.GetScopes() {
		if !slices.Contains(rt.Scopes, scope) {
			return empty, "", false, oidc.ErrInvalidScope()
		}
	}
	now := s.clock.Now()
	if err := s.validateRefreshTokenRequest(ctx, tx, rt, now); err != nil {
		var oauthErr *oidc.Error
		if errors.As(err, &oauthErr) {
			return empty, "", false, err
		}
		return empty, "", false, errRefreshGrantRefused()
	}
	tombstoned, err := q.IsRefreshFamilyRevoked(ctx, rt.FamilyID)
	if err != nil {
		return empty, "", false, err
	}
	graceChild := false
	if isRefreshTokenUsedOrRevoked(rt) || tombstoned {
		grace, err := s.refreshReuseGraceDecision(ctx, q, rt, now)
		if err != nil {
			return empty, "", false, err
		}
		switch grace {
		case graceIssue:
			graceChild = true
		case graceRefuse:
			s.auditRefreshReuseGrace(ctx, rt.UserID, rt.FamilyID, "refused")
			return empty, "", false, errRefreshGrantRefused()
		default:
			if err := revokeRefreshFamilyOnReuse(ctx, q, rt.FamilyID, now); err != nil {
				return empty, "", false, err
			}
			created, err := tombstoneRefreshFamily(ctx, q, rt.FamilyID, rt.UserID, tombstoneReasonReuse, now)
			if err != nil {
				return empty, "", false, err
			}
			if err := s.auditRefreshReuseDetectionTx(ctx, q, rt.UserID, rt.FamilyID, created); err != nil {
				return empty, "", false, err
			}
			if err := tx.Commit(); err != nil {
				return empty, "", false, err
			}
			return empty, "", false, errRefreshGrantRefused()
		}
	}
	if !graceChild {
		if err := q.MarkRefreshTokenUsedAndRevokedByID(ctx, storeq.MarkRefreshTokenUsedAndRevokedByIDParams{ID: rt.ID, UsedAt: sql.NullTime{Time: now, Valid: true}}); err != nil {
			return empty, "", false, err
		}
	}
	// RFC 6749 §6: replacement refresh tokens retain the original grant scope,
	// even when the provider has narrowed the access token's current scopes.
	return refreshTokenAttributes{familyID: rt.FamilyID, userID: rt.UserID, clientID: rt.ClientID, resource: rt.Resource, scopes: rt.Scopes}, rt.ID, graceChild, nil
}
