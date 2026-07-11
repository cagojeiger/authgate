package storage

import (
	"context"
	"log/slog"
	"sync"
)

// clientRegistry owns the in-memory static client table and the active client
// resolution policy (the core in-memory lookup, optionally wrapped by the
// MCP/CIMD fallback). Storage holds one and delegates its client lookups here,
// keeping the registry out of the Storage adapter (#301).
type clientRegistry struct {
	clients sync.Map // client_id → *ClientModel
	policy  ClientResolutionPolicy
}

func newClientRegistry() *clientRegistry {
	r := &clientRegistry{}
	r.policy = coreClientResolutionPolicy{reg: r}
	return r
}

// Load populates the static registry from parsed client config entries.
// URL-form (CIMD-shaped) client_ids are rejected here: ResolveClient consults
// this map before the CIMD fetcher, so admitting a URL-form static entry would
// bypass every CIMDFetcher validation, so we log and skip rather than silently
// admit it.
func (r *clientRegistry) Load(clients []ClientConfigEntry) {
	for _, c := range clients {
		if IsCIMDClientID(c.ClientID) {
			slog.Warn("LoadClients: dropping URL-form client_id from static registry — use dynamic CIMD resolution instead",
				"client_id", c.ClientID)
			continue
		}
		cm := &ClientModel{
			ID:                   c.ClientID,
			SecretHash:           c.ClientSecretHash,
			Type:                 c.ClientType,
			LoginChannel:         c.LoginChannel,
			Name:                 c.Name,
			URL:                  c.URL,
			RedirectURIList:      StringArray(c.RedirectURIs),
			AllowedScopeList:     StringArray(c.AllowedScopes),
			AllowedGrantTypeList: StringArray(c.AllowedGrantTypes),
		}
		r.clients.Store(c.ClientID, cm)
	}
}

// SetPolicy overrides the resolution policy; a nil policy restores the core
// in-memory lookup.
func (r *clientRegistry) SetPolicy(policy ClientResolutionPolicy) {
	if policy == nil {
		r.policy = coreClientResolutionPolicy{reg: r}
		return
	}
	r.policy = policy
}

// Resolve looks up a client through the active policy.
func (r *clientRegistry) Resolve(ctx context.Context, clientID string) (*ClientModel, error) {
	if r.policy == nil {
		r.policy = coreClientResolutionPolicy{reg: r}
	}
	return r.policy.ResolveClient(ctx, clientID)
}
