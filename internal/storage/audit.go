package storage

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strings"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// Audit event type constants.
const (
	EventAuthRefreshReuseDetected = "auth.refresh_reuse_detected"
	EventAuthRefreshFamilyRevoked = "auth.refresh_family_revoked"
	EventAuthDeletionCompleted    = "auth.deletion_completed"
	EventAuthLogout               = "auth.logout"
	EventAuthTokenRevoked         = "auth.token_revoked"

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

func (s *Storage) AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error {
	ipAddress = normalizeIPAddress(ipAddress)
	var metaJSON []byte
	if metadata != nil {
		var err error
		metaJSON, err = json.Marshal(metadata)
		if err != nil {
			return err
		}
	}

	userIDValue := ""
	if userID != nil {
		userIDValue = *userID
	}

	return storeq.New(s.db).InsertAuditLog(ctx, storeq.InsertAuditLogParams{
		UserID:    userIDValue,
		EventType: eventType,
		IpAddress: nilIfEmpty(ipAddress),
		UserAgent: nilIfEmpty(userAgent),
		Metadata:  nilIfEmptyBytes(metaJSON),
		CreatedAt: s.clock.Now(),
	})
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
