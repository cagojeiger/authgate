package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

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

	// A token redeemed moments ago by a sibling request is not a theft signal:
	// clients that run several sessions on one stored credential refresh it
	// concurrently. Within the grace, issue another child into the same family
	// instead of revoking it.
	if isRefreshTokenUsedOrRevoked(rt) {
		switch grace, err := s.refreshReuseGraceDecision(ctx, qtx, rt, now); {
		case err != nil:
			return nil, err
		case grace == graceIssue:
			// Provisional: CreateAccessAndRefreshTokens decides again under the
			// row lock before it inserts, and audits the outcome.
			if err := s.validateRefreshTokenRequest(ctx, tx, rt, now); err != nil {
				return nil, err
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			rt.graceRedemption = true
			return rt, nil
		case grace == graceRefuse:
			// Past the cap but still inside the window: refuse this request, but
			// do not revoke the family the other sessions are using.
			s.auditRefreshReuseGrace(ctx, rt.UserID, rt.FamilyID, "refused")
			return nil, op.ErrInvalidRefreshToken
		}
	}

	// Already used/revoked → reuse detection → family revoke + tombstone
	if isRefreshTokenUsedOrRevoked(rt) {
		if err := revokeRefreshFamilyOnReuse(ctx, qtx, rt.FamilyID, now); err != nil {
			return nil, op.ErrInvalidRefreshToken
		}
		// Tombstone the family in the same tx as the revoke. RevokeRefreshFamily
		// only flips existing rows; the tombstone is what CreateAccessAndRefreshTokens
		// checks so a child rotating in just after the revoke is still refused.
		tombstoned, err := tombstoneRefreshFamily(ctx, qtx, rt.FamilyID, rt.UserID, tombstoneReasonReuse, now)
		if err != nil {
			return nil, op.ErrInvalidRefreshToken
		}
		// Every reuse is audited with the presenter's IP and user agent: in a
		// theft the attacker is often a later presenter (the victim trips
		// detection first, the attacker then presents its own now-revoked
		// token), and these rows are the only record of where it connected
		// from. The family revoke is audited once, by the request whose
		// tombstone insert won; ON CONFLICT DO NOTHING picks exactly one
		// transaction even when reuse requests race.
		//
		// The audit rows commit in the SAME transaction as the revoke and
		// tombstone, so they cannot be lost on their own. If any insert fails the
		// whole tx rolls back, the tombstone with it, and the client's retry
		// detects the reuse again and audits it then.
		if err := s.auditRefreshReuseDetectionTx(ctx, qtx, rt.UserID, rt.FamilyID, tombstoned); err != nil {
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

func (s *Storage) validateRefreshTokenRequest(ctx context.Context, tx *sql.Tx, rt *RefreshTokenModel, now time.Time) error {
	if now.After(rt.ExpiresAt) {
		return op.ErrInvalidRefreshToken
	}

	requestResource := ResourceFromContext(ctx)
	if err := s.resourcePolicy.ValidateTokenRequest(ctx, rt.ClientID, rt.Resource, requestResource); err != nil {
		return err
	}

	// The client's access policy is re-evaluated on every refresh so removing
	// an account from it takes effect within one access-token lifetime, not
	// only at the next interactive login.
	access := s.ensureRegistry().staticAccess(rt.ClientID)
	if s.stateChecker == nil && !access.Restricted() {
		return nil
	}
	user, err := s.getUserByID(ctx, tx, rt.UserID)
	if err != nil {
		return op.ErrInvalidRefreshToken
	}
	if s.stateChecker != nil {
		if err := s.stateChecker(user); err != nil {
			return &oidc.Error{ErrorType: "invalid_grant", Description: err.Error()}
		}
	}
	return s.enforceStaticClientAccess(ctx, access, rt.ClientID, "refresh", user)
}
