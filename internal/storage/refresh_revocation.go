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

// RevokeToken revokes the grant a refresh token belongs to: every token in its
// family, plus a tombstone so no further child can be issued into it. Revoking
// only the presented row stopped being enough once the reuse grace let a family
// hold more than one live token (the sibling a concurrent session received);
// RFC 7009 §2.1 lets the server revoke the whole grant.
//
// tokenOrTokenID is the refresh token itself, or its row id as zitadel/oidc
// passes it after GetRefreshTokenInfo.
func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	info := clientinfo.FromContext(ctx)
	revoked, grantUserID, err := s.revokeRefreshGrant(ctx, tokenOrTokenID, clientID)
	if err != nil {
		slog.ErrorContext(ctx, "revoke refresh grant", "error", err)
	}
	if revoked {
		// zitadel/oidc passes an empty subject when it could not resolve the
		// token itself; the grant's owner is known from the row.
		if grantUserID != "" {
			userID = grantUserID
		}
		s.AuditLog(ctx, &userID, EventAuthTokenRevoked, info.IP, info.UserAgent, map[string]any{
			"client_id":   clientID,
			"client_name": s.auditClientName(ctx, clientID),
		})
	}

	// RFC 7009: always return 200 regardless of whether anything was revoked
	return nil
}

// revokeRefreshGrant revokes the family of the refresh token identified by
// tokenOrTokenID and tombstones it, provided the token was issued to clientID;
// a token of another client is left alone (RFC 7009 §2.1), which the endpoint
// still answers with 200. It reports whether any live token was revoked and
// the grant's user.
func (s *Storage) revokeRefreshGrant(ctx context.Context, tokenOrTokenID, clientID string) (bool, string, error) {
	now := s.clock.Now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, "", err
	}
	defer func() { _ = tx.Rollback() }()
	qtx := storeq.New(tx)

	familyID, userID, err := lookupRefreshGrant(ctx, qtx, s.keys.RefreshHash(tokenOrTokenID), tokenOrTokenID, clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	n, err := qtx.RevokeRefreshFamily(ctx, storeq.RevokeRefreshFamilyParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		FamilyID:  familyID,
	})
	if err != nil {
		return false, "", err
	}
	if _, err := tombstoneRefreshFamily(ctx, qtx, familyID, userID, tombstoneReasonRevoked, now); err != nil {
		return false, "", err
	}
	if err := tx.Commit(); err != nil {
		return false, "", err
	}
	return n > 0, userID, nil
}

func lookupRefreshGrant(ctx context.Context, qtx *storeq.Queries, tokenHash, tokenID, clientID string) (familyID, userID string, err error) {
	row, err := qtx.GetRefreshTokenGrantByHash(ctx, storeq.GetRefreshTokenGrantByHashParams{TokenHash: tokenHash, ClientID: clientID})
	if err == nil {
		return row.FamilyID, row.UserID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", "", err
	}
	if _, perr := uuid.Parse(tokenID); perr != nil {
		return "", "", sql.ErrNoRows
	}
	byID, err := qtx.GetRefreshTokenGrantByID(ctx, storeq.GetRefreshTokenGrantByIDParams{ID: tokenID, ClientID: clientID})
	if err != nil {
		return "", "", err
	}
	return byID.FamilyID, byID.UserID, nil
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

func revokeRefreshFamilyOnReuse(ctx context.Context, qtx *storeq.Queries, familyID string, now time.Time) error {
	_, err := qtx.RevokeRefreshFamily(ctx, storeq.RevokeRefreshFamilyParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		FamilyID:  familyID,
	})
	return err
}

const (
	tombstoneReasonReuse   = "reuse_detected"
	tombstoneReasonRevoked = "revoked"
)

// tombstoneRefreshFamily records a permanent per-family tombstone so a child
// token cannot be issued into the family later (checked by
// CreateAccessAndRefreshTokens). Idempotent via ON CONFLICT DO NOTHING; it
// reports whether this call created the tombstone.
func tombstoneRefreshFamily(ctx context.Context, qtx *storeq.Queries, familyID, userID, reason string, now time.Time) (bool, error) {
	n, err := qtx.TombstoneRefreshFamily(ctx, storeq.TombstoneRefreshFamilyParams{
		FamilyID:  familyID,
		UserID:    userID,
		Reason:    reason,
		RevokedAt: now,
	})
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// auditRefreshReuseDetectionTx writes the reuse-detection audit row, and the
// family-revoked row when familyRevoked (this request created the tombstone),
// via the supplied transaction queries, so they commit atomically with the
// family revoke. An insert error is returned (not swallowed) so the
// caller can roll back the whole reuse-detection transaction.
func (s *Storage) auditRefreshReuseDetectionTx(ctx context.Context, qtx *storeq.Queries, userID, familyID string, familyRevoked bool) error {
	info := clientinfo.FromContext(ctx)
	if err := s.writeAuditLogTx(ctx, qtx, &userID, EventAuthRefreshReuseDetected, info.IP, info.UserAgent, map[string]any{"family_id": familyID}); err != nil {
		return err
	}
	if !familyRevoked {
		return nil
	}
	return s.writeAuditLogTx(ctx, qtx, &userID, EventAuthRefreshFamilyRevoked, info.IP, info.UserAgent, map[string]any{"family_id": familyID})
}
