package storage

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// Audit event type constants.
//
// auth.logout (session revoke via /end_session) and auth.token_revoked
// (refresh-token revoke via /oauth/revoke) are distinct: logout does NOT
// invalidate refresh tokens, so consumers must not treat it as full
// invalidation. See docs/spec/005-token-lifecycle.md "Logout vs. Revoke".
const (
	EventAuthRefreshReuseDetected = "auth.refresh_reuse_detected"
	EventAuthRefreshFamilyRevoked = "auth.refresh_family_revoked"
	// EventAuthTokenRefreshed is no longer emitted; successful refresh grants
	// are not audited. The constant remains because historical rows carry it.
	EventAuthTokenRefreshed    = "auth.token_refreshed"
	EventAuthDeletionRequested = "auth.deletion_requested"
	EventAuthDeletionCancelled = "auth.deletion_cancelled"
	EventAuthDeletionCompleted = "auth.deletion_completed"
	EventAuthLogout            = "auth.logout"
	EventAuthTokenRevoked      = "auth.token_revoked"
	EventAuthChannelMismatch   = "auth.channel_mismatch"
	EventAuthDeviceCodeIssued  = "auth.device_code_issued"
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
		SessionID: s.sessionAtRest(sessionID),
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
	s.ensureAudit().Log(ctx, userID, eventType, ipAddress, userAgent, metadata)
}

// writeAuditLogTx inserts an audit row inside the supplied transaction so the
// row commits atomically with the surrounding business write (see the
// refresh-reuse path in storage_auth_tokens.go).
func (s *Storage) writeAuditLogTx(ctx context.Context, qtx *storeq.Queries, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error {
	return s.ensureAudit().LogTx(ctx, qtx, userID, eventType, ipAddress, userAgent, metadata)
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
