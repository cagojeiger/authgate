package storage

import (
	"context"
	"fmt"
	"strings"
)

// DCRRequest represents an RFC 7591 Dynamic Client Registration request.
type DCRRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// DCRResponse represents an RFC 7591 Dynamic Client Registration response.
type DCRResponse struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// RegisterClient creates a new public OAuth client via DCR (RFC 7591).
func (s *Storage) RegisterClient(ctx context.Context, req *DCRRequest) (*DCRResponse, error) {
	// Validate redirect_uris
	if len(req.RedirectURIs) == 0 {
		return nil, fmt.Errorf("redirect_uris is required")
	}
	for _, uri := range req.RedirectURIs {
		if !isValidRedirectURI(uri) {
			return nil, fmt.Errorf("invalid redirect_uri: %s (must be http://localhost:* or https://)", uri)
		}
	}

	// Defaults
	if req.ClientName == "" {
		req.ClientName = "MCP Client"
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "none"
	}

	clientID := s.idgen.NewUUID()
	now := s.clock.Now()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oauth_clients (client_id, client_type, login_channel, name, redirect_uris, allowed_scopes, allowed_grant_types, created_at, updated_at)
		 VALUES ($1, 'public', 'mcp', $2, $3, $4, $5, $6, $6)`,
		clientID, req.ClientName,
		StringArray(req.RedirectURIs),
		StringArray([]string{"openid", "profile", "email", "offline_access"}),
		StringArray(req.GrantTypes),
		now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert client: %w", err)
	}

	return &DCRResponse{
		ClientID:                clientID,
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}, nil
}

// isValidRedirectURI checks that redirect URI is http://localhost:* or https://*.
func isValidRedirectURI(uri string) bool {
	if strings.HasPrefix(uri, "http://localhost:") || strings.HasPrefix(uri, "http://localhost/") || uri == "http://localhost" {
		return true
	}
	if strings.HasPrefix(uri, "http://127.0.0.1:") || strings.HasPrefix(uri, "http://127.0.0.1/") {
		return true
	}
	if strings.HasPrefix(uri, "https://") {
		return true
	}
	return false
}
