package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// refreshReuseGraceMaxIssued caps the children one redemption may have: the
// regular child plus grace children.
const refreshReuseGraceMaxIssued = 3

type refreshReuseGrace int

const (
	// graceNone: the grace does not apply; run reuse detection.
	graceNone refreshReuseGrace = iota
	// graceIssue: redeem the token again into the same family.
	graceIssue
	// graceRefuse: inside the window but the grace is exhausted or no longer
	// safe; refuse without revoking the family.
	graceRefuse
)

// refreshReuseGraceDecision decides how a redeemed refresh token presented
// again is handled. The grace applies only when all of these hold:
//
//   - the grace is enabled;
//   - the token was redeemed: used_at is set, and revoked in that same step.
//     Revocation (/oauth/revoke by hash or id, a user-wide revoke, account
//     deletion, a family revoke) never sets used_at, so a revoked token gets
//     no grace;
//   - the redemption was at most the grace ago;
//   - the family is not tombstoned by reuse detection.
//
// Inside the window the token is redeemed again (graceIssue) unless a token in
// the family has since been revoked on purpose, which would otherwise let a
// replay bring back a session its owner ended, or the redemption already has
// refreshReuseGraceMaxIssued children. Either refuses (graceRefuse).
//
// This runs twice: provisionally when the token is presented, and again under
// the redeemed row's lock right before the child is inserted
// (lockAndCheckGraceChild), which is what makes the cap exact.
func (s *Storage) refreshReuseGraceDecision(ctx context.Context, qtx *storeq.Queries, rt *RefreshTokenModel, now time.Time) (refreshReuseGrace, error) {
	if s.refreshReuseGrace <= 0 || rt.UsedAt == nil || rt.RevokedAt == nil || !rt.RevokedAt.Equal(*rt.UsedAt) {
		return graceNone, nil
	}
	if now.Sub(*rt.UsedAt) > s.refreshReuseGrace {
		return graceNone, nil
	}
	tombstoned, err := qtx.IsRefreshFamilyRevoked(ctx, rt.FamilyID)
	if err != nil {
		return graceNone, err
	}
	if tombstoned {
		return graceNone, nil
	}
	revokedOnPurpose, err := qtx.HasRevokedUnredeemedRefreshTokenInFamily(ctx, rt.FamilyID)
	if err != nil {
		return graceNone, err
	}
	if revokedOnPurpose {
		return graceNone, nil
	}
	children, err := s.countRedemptionChildren(ctx, qtx, rt)
	if err != nil {
		return graceNone, err
	}
	if children >= refreshReuseGraceMaxIssued {
		return graceRefuse, nil
	}
	return graceIssue, nil
}

// countRedemptionChildren counts the tokens rotated from rt. Tokens issued
// before parent_id existed have no parent recorded and are not counted.
func (s *Storage) countRedemptionChildren(ctx context.Context, qtx *storeq.Queries, rt *RefreshTokenModel) (int64, error) {
	return qtx.CountRefreshTokenChildren(ctx, rt.ID)
}

// errRefreshGrantRefused is returned when a refresh token is refused while the
// new tokens are being created. zitadel/oidc maps only *oidc.Error values from
// that step to their own status; a plain storage error there becomes a 500
// server_error, which invites the retry that trips reuse detection.
func errRefreshGrantRefused() error {
	return oidc.ErrInvalidGrant().WithParent(op.ErrInvalidRefreshToken)
}

// lockAndCheckGraceChild locks the refresh token being rotated and returns its
// id (the new child's parent) and whether the child is issued under the reuse
// grace. The lock is held until the caller's transaction ends, so requests
// redeeming the same token insert one at a time and each sees the children
// committed before it.
//
// The rotation is re-checked under the lock (account state, resource binding,
// and the full grace decision including the cap) when the request came through
// the grace (graceRequested) or the redemption already has a child. The first
// child of an ordinary rotation passes without it. A refusal inserts nothing.
//
// A missing row is refused: the token was redeemed a moment ago, so it can only
// have been deleted since (an account purge), and minting from it would start
// an unrelated family.
func (s *Storage) lockAndCheckGraceChild(ctx context.Context, tx *sql.Tx, qtx *storeq.Queries, tokenHash string, graceRequested bool, now time.Time) (string, bool, error) {
	rt, err := loadRefreshTokenForUpdate(ctx, qtx, tokenHash)
	if errors.Is(err, op.ErrInvalidRefreshToken) {
		return "", false, errRefreshGrantRefused()
	}
	if err != nil {
		return "", false, err
	}
	if rt.UsedAt == nil {
		return rt.ID, false, nil
	}
	children, err := s.countRedemptionChildren(ctx, qtx, rt)
	if err != nil {
		return "", false, err
	}
	if !graceRequested && children == 0 {
		return rt.ID, false, nil
	}
	if err := s.validateRefreshTokenRequest(ctx, tx, rt, now); err != nil {
		// Keep an OAuth error as it is (e.g. an inactive account); anything
		// else would reach the client as 500 from this step.
		var oerr *oidc.Error
		if errors.As(err, &oerr) {
			return "", false, err
		}
		return "", false, errRefreshGrantRefused()
	}
	grace, err := s.refreshReuseGraceDecision(ctx, qtx, rt, now)
	if err != nil {
		return "", false, err
	}
	if grace != graceIssue {
		s.auditRefreshReuseGrace(ctx, rt.UserID, rt.FamilyID, "refused")
		return "", false, errRefreshGrantRefused()
	}
	return rt.ID, graceRequested, nil
}

// auditRefreshReuseGrace records a redemption handled by the reuse grace with
// the presenter's IP and user agent. A replay inside the window is exactly what
// the grace lets through, so every grace child and every refusal is evidence.
func (s *Storage) auditRefreshReuseGrace(ctx context.Context, userID, familyID, outcome string) {
	info := clientinfo.FromContext(ctx)
	s.AuditLog(ctx, &userID, EventAuthRefreshReuseGrace, info.IP, info.UserAgent, map[string]any{
		"family_id": familyID,
		"outcome":   outcome,
	})
}
