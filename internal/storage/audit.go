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
// auth.logout (session revoke via /end_session) and auth.token_revoked
// (refresh-token revoke via /oauth/revoke) are distinct: logout does NOT
// invalidate refresh tokens, so consumers must not treat it as full
// invalidation. See docs/spec/005-token-lifecycle.md "Logout vs. Revoke".
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
	params, err := s.prepareAuditRow(ctx, userID, eventType, ipAddress, userAgent, metadata)
	if err != nil {
		slog.ErrorContext(ctx, "audit log: marshal metadata",
			"event_type", eventType,
			"user_id", userIDLogValue(userID),
			"error", err,
		)
		return
	}
	if err := storeq.New(s.db).InsertAuditLog(ctx, params); err != nil {
		slog.ErrorContext(ctx, "audit log: insert",
			"event_type", eventType,
			"user_id", userIDLogValue(userID),
			"error", err,
		)
	}
}

// writeAuditLogTx inserts an audit row using the supplied transaction queries
// so the row commits atomically with the surrounding business write (see the
// refresh-reuse path in storage_auth_tokens.go). Unlike AuditLog it returns the
// error instead of swallowing it, so transactional callers can roll back.
func (s *Storage) writeAuditLogTx(ctx context.Context, qtx *storeq.Queries, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error {
	params, err := s.prepareAuditRow(ctx, userID, eventType, ipAddress, userAgent, metadata)
	if err != nil {
		return err
	}
	return qtx.InsertAuditLog(ctx, params)
}

// prepareAuditRow normalizes, sanitizes and marshals an audit event into insert
// params. It performs no DB access, so both the best-effort AuditLog path and
// the transactional writeAuditLogTx path share identical sanitization.
func (s *Storage) prepareAuditRow(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) (storeq.InsertAuditLogParams, error) {
	ipAddress = normalizeIPAddress(ipAddress)
	metadata = s.sanitizeAuditMetadata(ctx, eventType, metadata)
	var metaJSON []byte
	if metadata != nil {
		marshaled, err := json.Marshal(metadata)
		if err != nil {
			return storeq.InsertAuditLogParams{}, err
		}
		metaJSON = marshaled
	}
	return storeq.InsertAuditLogParams{
		UserID:    userIDLogValue(userID),
		EventType: eventType,
		IpAddress: nilIfEmpty(ipAddress),
		UserAgent: nilIfEmpty(userAgent),
		Metadata:  nilIfEmptyBytes(metaJSON),
		CreatedAt: s.clock.Now(),
	}, nil
}

func (s *Storage) sanitizeAuditMetadata(ctx context.Context, eventType string, metadata map[string]any) map[string]any {
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
	// session_id arrives as the raw session cookie value. Store only its hash so
	// an audit-log read cannot recover a live bearer (ADR-002). The hash matches
	// sessions.token_hash, so GetAuditClientContextBySessionID still correlates.
	if raw, ok := sanitized["session_id"].(string); ok && raw != "" {
		sanitized["session_id"] = s.sessionAtRest(raw)
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
