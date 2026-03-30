package storage

import (
	"context"
	"encoding/json"
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

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (user_id, event_type, ip_address, user_agent, metadata, created_at)
		 VALUES ($1, $2, $3::inet, $4, $5::jsonb, $6)`,
		userID, eventType, nilIfEmpty(ipAddress), userAgent, nilIfEmptyBytes(metaJSON), s.clock.Now(),
	)
	return err
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
