package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	EventAuthTokenRefreshed       = "auth.token_refreshed"
	EventAuthDeletionRequested    = "auth.deletion_requested"
	EventAuthDeletionCancelled    = "auth.deletion_cancelled"
	EventAuthDeletionCompleted    = "auth.deletion_completed"
	EventAuthLogout               = "auth.logout"
	EventAuthTokenRevoked         = "auth.token_revoked"
	EventAuthChannelMismatch      = "auth.channel_mismatch"
	EventAuthDeviceCodeIssued     = "auth.device_code_issued"
	EventAuthConnectionRevoked    = "auth.connection_revoked"
	EventAuthSessionRevoked       = "auth.session_revoked"
	EventAuthOtherSessionsRevoked = "auth.other_sessions_revoked"

	EventConsoleClientsListed     = "console.clients_listed"
	EventConsoleConnectionsListed = "console.connections_listed"
	EventConsoleSessionsListed    = "console.sessions_listed"
	EventConsoleAuditLogViewed    = "console.audit_log_viewed"
	EventConsoleAccessDenied      = "console.access_denied"
)

var auditMetadataAllowlist = map[string]map[string]struct{}{
	EventAuthChannelMismatch: {
		"expected_channel": {},
		"actual_channel":   {},
		"client_id":        {},
		"client_name":      {},
	},
	"auth.login": {
		"channel":        {},
		"session_id":     {},
		"client_id":      {},
		"client_name":    {},
		"reused_session": {},
		"signup":         {},
	},
	"auth.signup": {
		"channel":     {},
		"client_id":   {},
		"client_name": {},
	},
	"auth.inactive_user": {
		"status":  {},
		"channel": {},
		"phase":   {},
	},
	EventAuthDeletionRequested: {
		"channel":     {},
		"client_id":   {},
		"client_name": {},
		"session_id":  {},
	},
	EventAuthDeletionCancelled: {
		"channel":     {},
		"client_id":   {},
		"client_name": {},
		"session_id":  {},
	},
	EventAuthDeletionCompleted: {
		"reason": {},
	},
	"auth.device_denied": {
		"client_id":   {},
		"client_name": {},
	},
	"auth.device_approved": {
		"client_id":   {},
		"client_name": {},
	},
	EventAuthDeviceCodeIssued: {
		"client_id":   {},
		"client_name": {},
	},
	EventAuthConnectionRevoked: {
		"client_id":   {},
		"client_name": {},
	},
	EventAuthSessionRevoked: {
		"session_id": {},
	},
	EventAuthOtherSessionsRevoked: {
		"current_session_id": {},
	},
	EventAuthTokenRefreshed: {
		"client_id":   {},
		"client_name": {},
		"family_id":   {},
	},
	EventAuthLogout: {
		"client_id":   {},
		"client_name": {},
	},
	EventAuthTokenRevoked: {
		"client_id":   {},
		"client_name": {},
	},
	EventAuthRefreshReuseDetected: {
		"family_id": {},
	},
	EventAuthRefreshFamilyRevoked: {
		"family_id": {},
	},
	EventConsoleClientsListed: {
		"result_count": {},
	},
	EventConsoleConnectionsListed: {
		"result_count": {},
	},
	EventConsoleSessionsListed: {
		"result_count": {},
	},
	EventConsoleAuditLogViewed: {
		"page":         {},
		"limit":        {},
		"result_count": {},
	},
	EventConsoleAccessDenied: {
		"operation":   {},
		"status_code": {},
		"reason":      {},
		"user_status": {},
	},
}

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

type AuditClientContext struct {
	ClientID   string
	ClientName string
}

func (s *Storage) GetAuditClientContextBySessionID(ctx context.Context, userID, sessionID string) (AuditClientContext, error) {
	row, err := storeq.New(s.db).GetAuditClientContextBySessionID(ctx, storeq.GetAuditClientContextBySessionIDParams{
		UserID:    userID,
		SessionID: sessionID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return AuditClientContext{}, ErrNotFound
	}
	if err != nil {
		return AuditClientContext{}, err
	}
	return AuditClientContext{ClientID: row.ClientID, ClientName: row.ClientName}, nil
}

// AuditLog records a security/audit event on a best-effort basis. Failures are
// logged via slog.ErrorContext but never propagated: callers have already
// committed the underlying business transaction (login, token issue, etc.) and
// must not be failed by an audit-write error. The metadata payload is *not*
// included in failure logs to avoid leaking session/family identifiers.
func (s *Storage) AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) {
	ipAddress = normalizeIPAddress(ipAddress)
	metadata = sanitizeAuditMetadata(ctx, eventType, metadata)
	var metaJSON []byte
	if metadata != nil {
		marshaled, err := json.Marshal(metadata)
		if err != nil {
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
		slog.ErrorContext(ctx, "audit log: insert",
			"event_type", eventType,
			"user_id", userIDLogValue(userID),
			"error", err,
		)
		return
	}
}

func sanitizeAuditMetadata(ctx context.Context, eventType string, metadata map[string]any) map[string]any {
	if len(metadata) == 0 {
		return nil
	}

	allowed, ok := auditMetadataAllowlist[eventType]
	if !ok || len(allowed) == 0 {
		slog.WarnContext(ctx, "audit log: metadata dropped for unknown event type",
			"event_type", eventType,
			"dropped_count", len(metadata),
		)
		return nil
	}

	sanitized := make(map[string]any, len(metadata))
	dropped := 0
	for key, value := range metadata {
		if _, ok := allowed[key]; !ok {
			dropped++
			continue
		}
		sanitized[key] = value
	}
	if dropped > 0 {
		slog.WarnContext(ctx, "audit log: metadata keys dropped",
			"event_type", eventType,
			"dropped_count", dropped,
		)
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
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
