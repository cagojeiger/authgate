package upstream

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
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
	rpOpts      []rp.Option
	internalURL string
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

// NewOIDCProvider creates a provider by performing OIDC Discovery on the issuer URL.
func NewOIDCProvider(ctx context.Context, issuerURL, clientID, clientSecret, redirectURI string, opts ...Option) (*OIDCProvider, error) {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	if o.internalURL != "" {
		issuerParsed, _ := url.Parse(issuerURL)
		internalParsed, _ := url.Parse(o.internalURL)
		if issuerParsed != nil && internalParsed != nil {
			o.rpOpts = append(o.rpOpts, rp.WithHTTPClient(&http.Client{
				Transport: &hostRewriteTransport{
					fromHost:  issuerParsed.Host,
					toHost:    internalParsed.Host,
					toScheme:  internalParsed.Scheme,
					transport: http.DefaultTransport,
				},
			}))
		}
	}

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

func (p *OIDCProvider) AuthURL(state string) string {
	return rp.AuthURL(state, p.rp)
}

func (p *OIDCProvider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, p.rp)
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}

	info, err := rp.Userinfo[*oidc.UserInfo](ctx, tokens.AccessToken, tokens.TokenType, tokens.IDTokenClaims.GetSubject(), p.rp)
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}

	return &UserInfo{
		Sub:           info.Subject,
		Email:         info.Email,
		EmailVerified: bool(info.EmailVerified),
		Name:          info.Name,
		Picture:       info.Picture,
	}, nil
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
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return parts[0]
}
