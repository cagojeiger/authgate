package storage

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type verifiedAccessTokenKey struct{}

// WrapVerifiedAccessToken supplements the provider's signature/issuer/expiry
// verification with AuthGate's access-token profile. Claims reach Storage only
// after verification; the provider still owns request parsing and client auth.
func WrapVerifiedAccessToken(inner http.Handler, issuer string) http.Handler {
	p, supported := inner.(op.UserinfoProvider)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userinfo := r.URL.Path == "/userinfo"
		if !userinfo && r.URL.Path != "/oauth/introspect" {
			inner.ServeHTTP(w, r)
			return
		}
		ctx := op.ContextWithIssuer(r.Context(), issuer)
		var claims *oidc.AccessTokenClaims
		if supported {
			var token string
			var err error
			if userinfo {
				token, err = op.ParseUserinfoRequest(r, p.Decoder())
			} else {
				err = r.ParseForm()
				token = r.Form.Get("token")
			}
			if err == nil {
				claims, _ = verifyAccessTokenProfile(ctx, token, p.AccessTokenVerifier(ctx))
			}
		}
		if userinfo {
			// AuthGate's OIDC tokens target their client. Resource-bound tokens target
			// that API, not this endpoint, even when they include an openid scope.
			if claims == nil || !slices.Contains(claims.Audience, claims.ClientID) {
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				http.Error(w, "access token invalid", http.StatusUnauthorized)
				return
			}
			if !slices.Contains(claims.Scopes, "openid") {
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="openid"`)
				http.Error(w, "openid scope required", http.StatusForbidden)
				return
			}
		}
		// An invalid introspection token must still pass through client
		// authentication. Storage then returns an inactive result, with no claims.
		if claims != nil {
			ctx = context.WithValue(ctx, verifiedAccessTokenKey{}, claims)
		}
		inner.ServeHTTP(w, r.WithContext(ctx))
	})
}

func verifyAccessTokenProfile(ctx context.Context, token string, verifier *op.AccessTokenVerifier) (*oidc.AccessTokenClaims, error) {
	signed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(signed.Signatures) != 1 {
		return nil, errors.New("invalid access token signature header")
	}
	typ := signed.Signatures[0].Protected.ExtraHeaders[jose.HeaderType]
	if typ != "at+jwt" && typ != "application/at+jwt" {
		return nil, errors.New("invalid access token type")
	}
	// Do not mutate the provider's shared verifier.
	v := *verifier
	v.SupportedSignAlgs = []string{string(jose.RS256)}
	claims, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, token, &v)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if claims.Issuer == "" || claims.Subject == "" || claims.ClientID == "" || claims.JWTID == "" || len(claims.Audience) == 0 || slices.Contains(claims.Audience, "") || claims.Expiration.AsTime().IsZero() || claims.IssuedAt.AsTime().IsZero() || claims.IssuedAt.AsTime().After(now) || claims.NotBefore.AsTime().After(now) {
		return nil, errors.New("invalid access token claims")
	}
	return claims, nil
}

func verifiedTokenClaims(ctx context.Context, tokenID, subject string) (*oidc.AccessTokenClaims, error) {
	claims, ok := ctx.Value(verifiedAccessTokenKey{}).(*oidc.AccessTokenClaims)
	if !ok || claims.JWTID != tokenID || claims.Subject != subject {
		return nil, errors.New("verified access token required")
	}
	return claims, nil
}
