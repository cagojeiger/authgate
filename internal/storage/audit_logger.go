package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// auditLogger owns audit-row writing: metadata sanitization, marshalling and
// insertion (both best-effort and transactional). Storage holds one and
// delegates AuditLog / writeAuditLogTx here, keeping audit plumbing out of the
// Storage adapter (#301). sessionHash injects Storage.sessionAtRest so a raw
// session_id in metadata is stored as its lookup hash (ADR-002) without the
// logger reaching back into Storage's crypto keys directly.
type auditLogger struct {
	db          *sql.DB
	clock       clock.Clock
	sessionHash func(string) string
}

func newAuditLogger(db *sql.DB, clk clock.Clock, sessionHash func(string) string) *auditLogger {
	return &auditLogger{db: db, clock: clk, sessionHash: sessionHash}
}

// Log records a security/audit event on a best-effort basis. Failures are
// logged via slog.ErrorContext but never propagated: callers have already
// committed the underlying business transaction (login, token issue, etc.) and
// must not be failed by an audit-write error. The metadata payload is *not*
// included in failure logs to avoid leaking session/family identifiers.
func (a *auditLogger) Log(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) {
	params, err := a.prepareRow(ctx, userID, eventType, ipAddress, userAgent, metadata)
	if err != nil {
		slog.ErrorContext(ctx, "audit log: marshal metadata",
			"event_type", eventType,
			"user_id", userIDLogValue(userID),
			"error", err,
		)
		return
	}
	if err := storeq.New(a.db).InsertAuditLog(ctx, params); err != nil {
		slog.ErrorContext(ctx, "audit log: insert",
			"event_type", eventType,
			"user_id", userIDLogValue(userID),
			"error", err,
		)
	}
}

// LogTx inserts an audit row using the supplied transaction queries so the row
// commits atomically with the surrounding business write (see the refresh-reuse
// path in storage_auth_tokens.go). Unlike Log it returns the error instead of
// swallowing it, so transactional callers can roll back.
func (a *auditLogger) LogTx(ctx context.Context, qtx *storeq.Queries, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error {
	params, err := a.prepareRow(ctx, userID, eventType, ipAddress, userAgent, metadata)
	if err != nil {
		return err
	}
	return qtx.InsertAuditLog(ctx, params)
}

// prepareRow normalizes, sanitizes and marshals an audit event into insert
// params. It performs no DB access, so both the best-effort Log path and the
// transactional LogTx path share identical sanitization.
func (a *auditLogger) prepareRow(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) (storeq.InsertAuditLogParams, error) {
	ipAddress = normalizeIPAddress(ipAddress)
	metadata = a.sanitize(ctx, eventType, metadata)
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
		CreatedAt: a.clock.Now(),
	}, nil
}

func (a *auditLogger) sanitize(ctx context.Context, eventType string, metadata map[string]any) map[string]any {
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
		sanitized["session_id"] = a.sessionHash(raw)
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}
