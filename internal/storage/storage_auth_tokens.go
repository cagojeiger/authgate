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
	resource := ResourceFromContext(ctx)
	// #184: validate the channel × resource matrix on every /authorize, not
	// only when resource is empty.
	client, err := s.ResolveClient(ctx, req.ClientID)
	if err == nil {
		if err := s.resourcePolicy.ValidateAuthorizeRequest(ctx, client, resource); err != nil {
			return nil, err
		}
	}

	// PKCE stays mandatory unless a confidential client opted out. An
	// unresolvable client keeps the requirement: never relax on a lookup
	// failure. zitadel rejects the unknown client_id right after this.
	if err != nil || !client.SkipPKCE {
		if req.CodeChallenge == "" || req.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
			err := oidc.ErrInvalidRequest()
			err.Description = "PKCE S256 required"
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

// TerminateSession revokes the user's server-side session rows only; per OIDC
// RP-Initiated Logout 1.0 §2 vs RFC 7009 it does NOT revoke refresh tokens (RPs
// must call /oauth/revoke). See docs/spec/005-token-lifecycle.md "Logout vs.
// Revoke".
func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	n, err := storeq.New(s.db).RevokeSessionsByUserID(ctx, storeq.RevokeSessionsByUserIDParams{
		RevokedAt: sql.NullTime{Time: s.clock.Now(), Valid: true},
		UserID:    userID,
	})
	if err != nil {
		return err
	}
	// Audit a logout only when it ended something, so replayed or duplicate
	// logout requests do not add rows for sessions that were already gone.
	if n == 0 {
		return nil
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
