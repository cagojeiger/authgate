// MCP Server example — authenticated "me" tool using authgate tokens.
// Runs over Streamable HTTP transport with JWT Bearer authentication.
//
// Usage: go run ./examples/mcp-server/
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func protectedResourceMetadataURL(resourceURL string) (string, string, error) {
	u, err := url.Parse(resourceURL)
	if err != nil {
		return "", "", err
	}
	wellKnownPath := "/.well-known/oauth-protected-resource"
	metadataPath := wellKnownPath
	if cleaned := strings.TrimPrefix(path.Clean(u.EscapedPath()), "/"); cleaned != "" && cleaned != "." {
		metadataPath = wellKnownPath + "/" + cleaned
	}

	metadataURL := *u
	metadataURL.RawQuery = ""
	metadataURL.Fragment = ""
	metadataURL.Path = metadataPath
	metadataURL.RawPath = metadataPath
	return metadataURL.String(), metadataPath, nil
}

// --- JWT verification ---

type Claims struct {
	Sub   string   `json:"sub"`
	Email string   `json:"email"`
	Name  string   `json:"name"`
	Iss   string   `json:"iss"`
	Aud   any      `json:"aud"`
	Scope string   `json:"scope"`
	Scp   []string `json:"scp"`
	Exp   int64    `json:"exp"`
}

type JWKSVerifier struct {
	jwksURL   string
	issuer    string
	audience  string
	mu        sync.RWMutex
	keys      *jose.JSONWebKeySet
	fetchedAt time.Time
	client    *http.Client
}

func NewJWKSVerifier(jwksURL, issuer, audience string) *JWKSVerifier {
	return &JWKSVerifier{
		jwksURL:  jwksURL,
		issuer:   issuer,
		audience: audience,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (v *JWKSVerifier) fetchKeys(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", v.jwksURL, nil)
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var keys jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return err
	}
	v.mu.Lock()
	v.keys = &keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

func (v *JWKSVerifier) Verify(ctx context.Context, token string) (*Claims, error) {
	sig, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}

	v.mu.RLock()
	keys := v.keys
	age := time.Since(v.fetchedAt)
	v.mu.RUnlock()
	if keys == nil || age > 5*time.Minute {
		if err := v.fetchKeys(ctx); err != nil && keys == nil {
			return nil, fmt.Errorf("jwks fetch: %w", err)
		}
		v.mu.RLock()
		keys = v.keys
		v.mu.RUnlock()
	}

	kid := ""
	if len(sig.Signatures) > 0 {
		kid = sig.Signatures[0].Header.KeyID
	}
	matchedKeys := keys.Key(kid)
	if len(matchedKeys) == 0 {
		v.fetchKeys(ctx)
		v.mu.RLock()
		matchedKeys = v.keys.Key(kid)
		v.mu.RUnlock()
		if len(matchedKeys) == 0 {
			return nil, fmt.Errorf("no key for kid %q", kid)
		}
	}

	payload, err := sig.Verify(matchedKeys[0])
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}

	var claims Claims
	json.Unmarshal(payload, &claims)
	if claims.Exp < time.Now().Unix() {
		return nil, fmt.Errorf("token expired")
	}
	if claims.Iss != v.issuer {
		return nil, fmt.Errorf("issuer mismatch: %s", claims.Iss)
	}
	if !containsAudience(claims.Aud, v.audience) {
		return nil, fmt.Errorf("audience mismatch")
	}
	return &claims, nil
}

func containsAudience(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			s, ok := item.(string)
			if ok && s == expected {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if item == expected {
				return true
			}
		}
	}
	return false
}

func hasScope(claims *Claims, requiredScope string) bool {
	if requiredScope == "" {
		return true
	}
	for _, s := range strings.Fields(claims.Scope) {
		if s == requiredScope {
			return true
		}
	}
	for _, s := range claims.Scp {
		if s == requiredScope {
			return true
		}
	}
	return false
}

// --- Auth middleware ---

type contextKey string

const claimsCtxKey contextKey = "claims"

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

// quickParseClaims extracts claims from JWT without signature verification.
// Used inside tool handler where the token was already verified by middleware.
func quickParseClaims(token string) *Claims {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var c Claims
	json.Unmarshal(payload, &c)
	return &c
}

func fetchUserinfo(authgateURL, accessToken string) (*Claims, error) {
	req, _ := http.NewRequest("GET", authgateURL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("userinfo: %d", resp.StatusCode)
	}
	var c Claims
	json.NewDecoder(resp.Body).Decode(&c)
	return &c, nil
}

func authMiddleware(verifier *JWKSVerifier, authgateURL, resourceMetadataURL, requiredScope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Public endpoints — no auth required
		if r.URL.Path == "/health" ||
			strings.HasPrefix(r.URL.Path, "/.well-known/") {
			next.ServeHTTP(w, r)
			return
		}

		token := extractBearerToken(r)
		if token == "" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s"`, resourceMetadataURL))
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		claims, err := verifier.Verify(r.Context(), token)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
			return
		}
		if !hasScope(claims, requiredScope) {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", scope="%s"`, requiredScope))
			http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
			return
		}
		// Enrich with userinfo (email, name)
		if ui, err := fetchUserinfo(authgateURL, token); err == nil {
			if ui.Email != "" {
				claims.Email = ui.Email
			}
			if ui.Name != "" {
				claims.Name = ui.Name
			}
		}
		ctx := context.WithValue(r.Context(), claimsCtxKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func main() {
	listenAddr := envOr("LISTEN_ADDR", ":9091")
	authgateURL := envOr("AUTHGATE_URL", "http://localhost:8080")
	resourceURL := envOr("RESOURCE_URL", "http://localhost:9091")
	requiredScope := envOr("REQUIRED_SCOPE", "openid")
	jwksURL := authgateURL + "/keys"
	resourceMetadataURL, resourceMetadataPath, err := protectedResourceMetadataURL(resourceURL)
	if err != nil {
		log.Fatalf("resource metadata url: %v", err)
	}

	verifier := NewJWKSVerifier(jwksURL, authgateURL, resourceURL)

	// Create MCP server
	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "authgate-mcp-server",
		Version: "1.0.0",
	}, nil)

	// Register "me" tool — returns authenticated user info
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "me",
		Description: "Returns the currently authenticated user's information (sub, email, name)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		claims, _ := ctx.Value(claimsCtxKey).(*Claims)
		if claims == nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: "error: not authenticated"},
				},
				IsError: true,
			}, nil, nil
		}

		info := map[string]string{
			"sub":   claims.Sub,
			"email": claims.Email,
			"name":  claims.Name,
		}
		data, _ := json.MarshalIndent(info, "", "  ")

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: string(data)},
			},
		}, nil, nil
	})

	// Streamable HTTP handler (supports single POST JSON-RPC calls)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return mcpServer
	}, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// RFC 8414: OAuth Authorization Server Metadata
	// MCP clients discover authgate's OAuth endpoints via this endpoint
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]any{
			"issuer":                                authgateURL,
			"authorization_endpoint":                authgateURL + "/authorize",
			"token_endpoint":                        authgateURL + "/oauth/token",
			"revocation_endpoint":                   authgateURL + "/oauth/revoke",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"none"},
			"client_id_metadata_document_supported": true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})

	// RFC 9728: OAuth Protected Resource Metadata (draft MCP spec)
	mux.HandleFunc(resourceMetadataPath, func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]any{
			"resource":              resourceURL,
			"authorization_servers": []string{authgateURL},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})

	mux.Handle("/mcp", mcpHandler)

	// Wrap entire mux with auth middleware
	handler := authMiddleware(verifier, authgateURL, resourceMetadataURL, requiredScope, mux)

	slog.Info("mcp-server starting", "addr", listenAddr, "authgate", authgateURL)
	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		log.Fatal(err)
	}
}
