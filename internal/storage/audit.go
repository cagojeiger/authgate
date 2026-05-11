package storage

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// Audit event type constants.
//
// EventAuthLogout vs EventAuthTokenRevoked (#191):
//
//   - `auth.logout` is emitted by `TerminateSession` when the user invokes
//     OIDC RP-Initiated Logout (`/end_session`). It revokes server-side
//     **session rows** (`sessions.revoked_at`) but does NOT touch active
//     refresh tokens — RFC 7009 token revocation and OIDC RP-Initiated
//     Logout 1.0 §2 are deliberately distinct concepts in the protocol.
//   - `auth.token_revoked` is emitted by `RevokeToken` when an RP calls
//     `/oauth/revoke` per RFC 7009 to retire a specific refresh token.
//   - Refresh tokens issued before `auth.logout` therefore remain valid
//     until their natural expiry, an explicit `/oauth/revoke`, or
//     reuse-detection family revoke (`auth.refresh_family_revoked`).
//
// Audit consumers MUST NOT treat `auth.logout` as "session **and** tokens
// fully invalidated" — see docs/spec/005-token-lifecycle.md "Logout vs.
// Revoke" for the contract.
const (
	EventAuthRefreshReuseDetected = "auth.refresh_reuse_detected"
	EventAuthRefreshFamilyRevoked = "auth.refresh_family_revoked"
	EventAuthDeletionCompleted    = "auth.deletion_completed"
	EventAuthLogout               = "auth.logout"
	EventAuthTokenRevoked         = "auth.token_revoked"
	EventAuthChannelMismatch      = "auth.channel_mismatch"

	EventTokenRefresh   = "token.refresh"
	EventTokenRevoked   = "token.revoked"
	EventSessionRevoked = "session.revoked"
	EventAccountDeleted = "account.deleted"
)

// normalizeIPAddress returns a bare IP address acceptable for PostgreSQL inet.
func normalizeIPAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if beforeComma, _, ok := strings.Cut(addr, ","); ok {
		addr = strings.TrimSpace(beforeComma)
	}
	if ip, err := netip.ParseAddr(addr); err == nil {
		return ip.String()
	}
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		if ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")); err == nil {
			return ip.String()
		}
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip, err := netip.ParseAddr(host); err == nil {
			return ip.String()
		}
	}
	return ""
}

// auditClientName returns the human-readable client name for clientID, or
// "" if it cannot be resolved. Used by storage-level audit call sites to
// embed `client_name` alongside `client_id` per #147.
func (s *Storage) auditClientName(ctx context.Context, clientID string) string {
	if clientID == "" {
		return ""
	}
	c, err := s.ResolveClient(ctx, clientID)
	if err != nil || c == nil {
		return ""
	}
	return c.Name
}

// AuditLog records a security/audit event on a best-effort basis. Failures are
// logged via slog.ErrorContext but never propagated: callers have already
// committed the underlying business transaction (login, token issue, etc.) and
// must not be failed by an audit-write error. The metadata payload is *not*
// included in failure logs to avoid leaking session/family identifiers.
func (s *Storage) AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) {
	ipAddress = normalizeIPAddress(ipAddress)
	var metaJSON []byte
	if metadata != nil {
		marshaled, err := json.Marshal(metadata)
		if err != nil {
			s.auditFailureRec.RecordWriteFailure("marshal")
			slog.ErrorContext(ctx, "audit log: marshal metadata",
				"event_type", eventType,
				"user_id", userIDLogValue(userID),
				"error", err,
			)
			return
		}
		metaJSON = marshaled
	}

	if err := storeq.New(s.db).InsertAuditLog(ctx, storeq.InsertAuditLogParams{
		UserID:    userIDLogValue(userID),
		EventType: eventType,
		IpAddress: nilIfEmpty(ipAddress),
		UserAgent: nilIfEmpty(userAgent),
		Metadata:  nilIfEmptyBytes(metaJSON),
		CreatedAt: s.clock.Now(),
	}); err != nil {
		s.auditFailureRec.RecordWriteFailure("insert")
		slog.ErrorContext(ctx, "audit log: insert",
			"event_type", eventType,
			"user_id", userIDLogValue(userID),
			"error", err,
		)
	}
}

func userIDLogValue(userID *string) string {
	if userID == nil {
		return ""
	}
	return *userID
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nilIfEmptyBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
