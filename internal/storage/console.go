package storage

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// ClientView is the safe read-only projection of a ClientModel for the console API.
// client_secret_hash is intentionally excluded.
type ClientView struct {
	ClientID      string   `json:"client_id"`
	Name          string   `json:"name"`
	URL           string   `json:"url,omitempty"`
	LoginChannel  string   `json:"login_channel"`
	AllowedScopes []string `json:"allowed_scopes"`
	RedirectURIs  []string `json:"redirect_uris"`
}

type ConnectionTokenInfo struct {
	ClientID string
	Scopes   []string
	LastUsed *time.Time
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
			URL:           c.URL,
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

// GetActiveConnections returns active client connections for which the user has
// a non-expired, non-revoked refresh token.
func (s *Storage) GetActiveConnections(ctx context.Context, userID string) ([]ConnectionTokenInfo, error) {
	rows, err := storeq.New(s.db).GetActiveConnectionsByUserID(ctx, storeq.GetActiveConnectionsByUserIDParams{
		UserID:    userID,
		ExpiresAt: s.clock.Now(),
	})
	if err != nil {
		return nil, err
	}
	connections := make([]ConnectionTokenInfo, 0, len(rows))
	for _, row := range rows {
		info := ConnectionTokenInfo{
			ClientID: row.ClientID,
			Scopes:   append([]string(nil), row.Scopes...),
		}
		if row.LastUsed.Valid {
			lastUsed := row.LastUsed.Time
			info.LastUsed = &lastUsed
		}
		connections = append(connections, info)
	}
	return connections, nil
}

func (s *Storage) RevokeConnection(ctx context.Context, userID, clientID string) error {
	return storeq.New(s.db).RevokeActiveRefreshTokensByUserIDAndClientID(ctx, storeq.RevokeActiveRefreshTokensByUserIDAndClientIDParams{
		RevokedAt: sql.NullTime{Time: s.clock.Now(), Valid: true},
		UserID:    userID,
		ClientID:  clientID,
	})
}

// ValidateBearerToken validates an access token JWT and returns the associated user.
// The token is verified against the current signing key using RS256.
func (s *Storage) ValidateBearerToken(ctx context.Context, authHeader string) (*User, error) {
	user, _, err := s.ValidateBearerTokenWithClientID(ctx, authHeader)
	return user, err
}

func (s *Storage) ValidateBearerTokenWithClientID(ctx context.Context, authHeader string) (*User, string, error) {
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader || token == "" {
		return nil, "", errors.New("missing bearer token")
	}
	if s.signingKey == nil {
		return nil, "", errors.New("signing key not configured")
	}

	tok, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, "", errors.New("invalid token format")
	}

	var claims josejwt.Claims
	if err := tok.Claims(s.signingKey.Public(), &claims); err != nil {
		return nil, "", errors.New("invalid token signature")
	}

	if err := claims.ValidateWithLeeway(josejwt.Expected{
		Time: s.clock.Now(),
	}, time.Second*5); err != nil {
		return nil, "", errors.New("token validation failed: " + err.Error())
	}

	if claims.Subject == "" {
		return nil, "", errors.New("missing sub claim")
	}

	// client_id is carried in the aud claim for browser/device flows
	clientID := ""
	if len(claims.Audience) > 0 {
		clientID = string(claims.Audience[0])
	}

	user, err := s.GetUserByID(ctx, claims.Subject)
	if err != nil {
		return nil, "", err
	}
	return user, clientID, nil
}
