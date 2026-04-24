package middleware

import (
	"net/http"
	"net/url"
	"strconv"
)

// NewCORSMiddleware returns an HTTP middleware that adds CORS headers for
// requests whose Origin matches one of the allowedOrigins (scheme+host).
//
// Preflight OPTIONS requests receive a 204 response with full CORS headers.
// Requests from unknown origins are passed through without CORS headers —
// the browser will enforce the same-origin policy on its own.
func NewCORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if o != "" {
			allowed[o] = struct{}{}
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			_, matched := allowed[origin]

			if matched {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Max-Age", strconv.Itoa(86400))
				// Vary header so caches don't mix responses for different origins.
				w.Header().Add("Vary", "Origin")
			}

			// Handle preflight.
			if r.Method == http.MethodOptions {
				if matched {
					w.WriteHeader(http.StatusNoContent)
				} else {
					w.WriteHeader(http.StatusNoContent)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// OriginsFromRedirectURIs extracts unique scheme+host values from a list of
// redirect URIs. These are used as the CORS allowed-origin list.
func OriginsFromRedirectURIs(uris []string) []string {
	seen := make(map[string]struct{})
	var origins []string
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		origin := u.Scheme + "://" + u.Host
		if _, ok := seen[origin]; !ok {
			seen[origin] = struct{}{}
			origins = append(origins, origin)
		}
	}
	return origins
}
