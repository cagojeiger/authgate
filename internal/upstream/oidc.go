package upstream

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// OIDCProvider uses zitadel/oidc RelyingParty for OIDC Discovery, token exchange, and userinfo.
type OIDCProvider struct {
	name string
	rp   rp.RelyingParty
}

// Option configures OIDCProvider construction.
type Option func(*options)

type options struct {
	rpOpts       []rp.Option
	internalURL  string
	httpTimeout  time.Duration
	cookieSecret string
	cookieSecure bool
	cookieSet    bool
}

// WithRPOptions passes options to the underlying rp.NewRelyingPartyOIDC.
func WithRPOptions(opts ...rp.Option) Option {
	return func(o *options) { o.rpOpts = append(o.rpOpts, opts...) }
}

// WithInternalURL rewrites outgoing HTTP requests from issuerURL host to internalURL host.
// Used in Docker/K8s where the browser reaches the IdP at localhost:8082
// but the server reaches it at mock-idp:8082 via internal DNS.
func WithInternalURL(internalURL string) Option {
	return func(o *options) { o.internalURL = internalURL }
}

// WithHTTPTimeout sets outbound HTTP timeout for OIDC discovery/token/userinfo calls.
func WithHTTPTimeout(timeout time.Duration) Option {
	return func(o *options) { o.httpTimeout = timeout }
}

// WithCookieSecret enables the high-level state/PKCE cookie protection. The
// secret seeds the cookie handler's hash and encryption keys (via SHA-256 with
// domain separation). secure=false allows the cookie over plain HTTP (dev mode).
func WithCookieSecret(secret string, secure bool) Option {
	return func(o *options) {
		o.cookieSecret = secret
		o.cookieSecure = secure
		o.cookieSet = true
	}
}

// NewOIDCProvider creates a provider by performing OIDC Discovery on the issuer URL.
func NewOIDCProvider(ctx context.Context, issuerURL, clientID, clientSecret, redirectURI string, opts ...Option) (*OIDCProvider, error) {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	transport := http.RoundTripper(http.DefaultTransport)
	if o.internalURL != "" {
		issuerParsed, _ := url.Parse(issuerURL)
		internalParsed, _ := url.Parse(o.internalURL)
		if issuerParsed != nil && internalParsed != nil {
			transport = &hostRewriteTransport{
				fromHost:  issuerParsed.Host,
				toHost:    internalParsed.Host,
				toScheme:  internalParsed.Scheme,
				transport: http.DefaultTransport,
			}
		}
	}
	if o.httpTimeout > 0 || o.internalURL != "" {
		client := &http.Client{
			Transport: transport,
		}
		if o.httpTimeout > 0 {
			client.Timeout = o.httpTimeout
		}
		o.rpOpts = append(o.rpOpts, rp.WithHTTPClient(client))
	}

	if o.cookieSet {
		hashKey := sha256.Sum256([]byte("authgate.upstream.cookie.hash:" + o.cookieSecret))
		encryptKey := sha256.Sum256([]byte("authgate.upstream.cookie.enc:" + o.cookieSecret))
		chOpts := []httphelper.CookieHandlerOpt{httphelper.WithMaxAge(600)}
		if !o.cookieSecure {
			chOpts = append(chOpts, httphelper.WithUnsecure())
		}
		ch := httphelper.NewCookieHandler(hashKey[:], encryptKey[:], chOpts...)
		o.rpOpts = append(o.rpOpts, rp.WithPKCE(ch))
	}

	// Sanitize the high-level handler's failure responses (invalid/missing
	// state cookie, PKCE mismatch, code-exchange error). The library default
	// echoes the internal error string back to the client; replace it with a
	// generic message so upstream OAuth error detail is not disclosed.
	o.rpOpts = append(o.rpOpts, rp.WithUnauthorizedHandler(func(w http.ResponseWriter, _ *http.Request, _ string, _ string) {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
	}))

	scopes := []string{"openid", "email", "profile"}
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, issuerURL, clientID, clientSecret, redirectURI, scopes, o.rpOpts...)
	if err != nil {
		return nil, fmt.Errorf("oidc relying party for %s: %w", issuerURL, err)
	}

	return &OIDCProvider{
		name: deriveProviderName(relyingParty.Issuer()),
		rp:   relyingParty,
	}, nil
}

func (p *OIDCProvider) Name() string { return p.name }

// Redirect sends the user to the upstream IdP, binding state to a CSRF cookie
// and (when PKCE is configured) a PKCE challenge cookie via the high-level
// AuthURLHandler.
func (p *OIDCProvider) Redirect(w http.ResponseWriter, r *http.Request, state string) {
	rp.AuthURLHandler(func() string { return state }, p.rp).ServeHTTP(w, r)
}

// Callback verifies the state cookie + PKCE, exchanges the code, fetches
// userinfo, and invokes onSuccess. On failure CodeExchangeHandler writes its
// own error response and onSuccess is not called.
func (p *OIDCProvider) Callback(w http.ResponseWriter, r *http.Request, onSuccess func(w http.ResponseWriter, r *http.Request, state string, info *UserInfo)) {
	cb := rp.UserinfoCallback[*oidc.IDTokenClaims, *oidc.UserInfo](
		func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, _ rp.RelyingParty, info *oidc.UserInfo) {
			onSuccess(w, r, state, mapUserInfo(info))
		},
	)
	rp.CodeExchangeHandler[*oidc.IDTokenClaims](cb, p.rp).ServeHTTP(w, r)
}

func mapUserInfo(info *oidc.UserInfo) *UserInfo {
	return &UserInfo{
		Sub:           info.Subject,
		Email:         info.Email,
		EmailVerified: bool(info.EmailVerified),
		Name:          info.Name,
	}
}

// hostRewriteTransport rewrites the host of outgoing HTTP requests.
// Bridges Docker internal DNS (mock-idp:8082) and browser-facing URLs (localhost:8082).
type hostRewriteTransport struct {
	fromHost  string
	toHost    string
	toScheme  string
	transport http.RoundTripper
}

func (t *hostRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == t.fromHost {
		req = req.Clone(req.Context())
		req.URL.Host = t.toHost
		if t.toScheme != "" {
			req.URL.Scheme = t.toScheme
		}
	}
	return t.transport.RoundTrip(req)
}

// deriveProviderName extracts a short name from the issuer URL.
func deriveProviderName(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return "unknown"
	}
	host := u.Hostname()
	if host == "" {
		return "unknown"
	}
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return parts[0]
}
