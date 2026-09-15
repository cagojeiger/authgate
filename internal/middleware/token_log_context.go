package middleware

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/kangheeyong/authgate/internal/logctx"
)

// TokenLogContext attaches client_id and grant_type to the log context of a
// token-style request, so the "request error" lines zitadel/oidc writes for a
// failed grant say which client failed and how.
//
// client_id comes from the form, or from the HTTP Basic username when the
// client authenticates with client_secret_basic (RFC 6749 §2.3.1 form-encodes
// it). The Basic password is never read. Parsing the form here is safe for the
// handlers downstream: ParseForm is idempotent and the parsed values travel
// with the request.
func TokenLogContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var attrs []slog.Attr
		if err := r.ParseForm(); err == nil {
			if clientID := tokenRequestClientID(r); clientID != "" {
				attrs = append(attrs, slog.String("client_id", clientID))
			}
			if grantType := strings.TrimSpace(r.PostForm.Get("grant_type")); grantType != "" {
				attrs = append(attrs, slog.String("grant_type", grantType))
			}
		}
		if len(attrs) > 0 {
			r = r.WithContext(logctx.With(r.Context(), attrs...))
		}
		next.ServeHTTP(w, r)
	})
}

func tokenRequestClientID(r *http.Request) string {
	if clientID := strings.TrimSpace(r.PostForm.Get("client_id")); clientID != "" {
		return clientID
	}
	username, _, ok := r.BasicAuth()
	if !ok {
		return ""
	}
	if decoded, err := url.QueryUnescape(username); err == nil {
		username = decoded
	}
	return strings.TrimSpace(username)
}
