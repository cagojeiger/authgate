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

			// Handle preflight.
			if r.Method == http.MethodOptions {
				if matched {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
					w.Header().Set("Access-Control-Allow-Credentials", "true")
					w.Header().Set("Access-Control-Max-Age", strconv.Itoa(86400))
					w.Header().Add("Vary", "Origin")
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// For non-preflight: wrap the writer so we can enforce CORS headers
			// right before they are committed, overriding any headers that
			// downstream handlers (e.g. zitadel/oidc) may have set themselves.
			cw := &corsWriter{ResponseWriter: w, origin: origin, matched: matched}
			next.ServeHTTP(cw, r)
			if !cw.written {
				cw.flushCORSHeaders()
			}
		})
	}
}

// corsWriter intercepts WriteHeader so CORS headers can be enforced or stripped
// just before the response is committed, regardless of what downstream set.
type corsWriter struct {
	http.ResponseWriter
	origin  string
	matched bool
	written bool
}

func (c *corsWriter) WriteHeader(code int) {
	c.flushCORSHeaders()
	c.ResponseWriter.WriteHeader(code)
}

func (c *corsWriter) Write(b []byte) (int, error) {
	if !c.written {
		c.flushCORSHeaders()
	}
	return c.ResponseWriter.Write(b)
}

func (c *corsWriter) flushCORSHeaders() {
	if c.written {
		return
	}
	c.written = true
	h := c.ResponseWriter.Header()
	if c.matched {
		h.Set("Access-Control-Allow-Origin", c.origin)
		h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Add("Vary", "Origin")
	} else {
		h.Del("Access-Control-Allow-Origin")
		h.Del("Access-Control-Allow-Methods")
		h.Del("Access-Control-Allow-Headers")
		h.Del("Access-Control-Allow-Credentials")
		h.Del("Access-Control-Max-Age")
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
