package service

import (
	"context"

	"github.com/kangheeyong/authgate/internal/storage"
)

// clientResolver is the minimal slice of the storage interface needed to
// look up a client's display name for audit metadata. Each service's store
// interface includes ResolveClient so this helper accepts the full store
// without ceremony.
type clientResolver interface {
	ResolveClient(ctx context.Context, clientID string) (*storage.ClientModel, error)
}

// resolveClientName returns the human-readable name for clientID, or an
// empty string when the client cannot be resolved (CIMD URL whose document
// is no longer cached, removed registry entry, lookup error). Used by audit
// call sites to embed `client_name` alongside `client_id` so audit rows
// remain renderable after the connection is revoked or the client_id is
// retired (#147).
func resolveClientName(ctx context.Context, store clientResolver, clientID string) string {
	if clientID == "" {
		return ""
	}
	c, err := store.ResolveClient(ctx, clientID)
	if err != nil || c == nil {
		return ""
	}
	return c.Name
}
