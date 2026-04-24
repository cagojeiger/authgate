package storage

import (
	"context"
	"sort"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// ClientView is the safe read-only projection of a ClientModel for the console API.
// client_secret_hash is intentionally excluded.
type ClientView struct {
	ClientID      string   `json:"client_id"`
	Name          string   `json:"name"`
	LoginChannel  string   `json:"login_channel"`
	AllowedScopes []string `json:"allowed_scopes"`
	RedirectURIs  []string `json:"redirect_uris"`
}

// ListAllClients returns all registered OAuth clients from the in-memory store,
// sorted by client_id for deterministic ordering.
func (s *Storage) ListAllClients() []ClientView {
	var views []ClientView
	s.clients.Range(func(_, value any) bool {
		c := value.(*ClientModel)
		views = append(views, ClientView{
			ClientID:      c.ID,
			Name:          c.Name,
			LoginChannel:  c.LoginChannel,
			AllowedScopes: append([]string(nil), c.AllowedScopeList...),
			RedirectURIs:  append([]string(nil), c.RedirectURIList...),
		})
		return true
	})
	sort.Slice(views, func(i, j int) bool {
		return views[i].ClientID < views[j].ClientID
	})
	return views
}

// GetActiveConnections returns the distinct client IDs for which the user has
// a non-expired, non-revoked refresh token.
func (s *Storage) GetActiveConnections(ctx context.Context, userID string) ([]string, error) {
	return storeq.New(s.db).GetActiveConnectionsByUserID(ctx, storeq.GetActiveConnectionsByUserIDParams{
		UserID:    userID,
		ExpiresAt: s.clock.Now(),
	})
}
