package notification

import (
	"context"
	"log/slog"

	"github.com/kangheeyong/authgate/internal/storage"
)

type AuditEnqueuer struct {
	store   *Store
	events  map[string]struct{}
	enabled bool
}

func NewAuditEnqueuer(store *Store, eventTypes []string, enabled bool) *AuditEnqueuer {
	events := make(map[string]struct{}, len(eventTypes))
	for _, eventType := range eventTypes {
		if eventType != "" {
			events[eventType] = struct{}{}
		}
	}
	return &AuditEnqueuer{store: store, events: events, enabled: enabled}
}

func (e *AuditEnqueuer) OnAuditLog(ctx context.Context, event storage.AuditEvent) {
	if !e.enabled {
		return
	}
	if _, ok := e.events[event.EventType]; !ok {
		return
	}
	if err := e.store.EnqueueAuditEvent(ctx, event); err != nil {
		slog.ErrorContext(ctx, "notification outbox: enqueue audit event",
			"event_type", event.EventType,
			"error", err,
		)
	}
}
