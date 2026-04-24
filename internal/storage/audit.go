package storage

import (
	"context"
	"encoding/json"

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

func (s *Storage) AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error {
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
