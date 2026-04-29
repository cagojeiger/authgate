package clientinfo

import (
	"net"
	"net/http"
)

// Middleware extracts client info on every request and attaches it to the
// request context for downstream handlers and services. It performs no
// rejection or rewriting of the request itself. The attached Info is always
// non-nil (zero value when extraction yields no IP), so callers can rely on
// FromContext returning a usable value without nil checks. Wire it as the
// outermost http.Handler so the context propagates through every other
// middleware.
func Middleware(trusted []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := Extract(r, trusted)
			next.ServeHTTP(w, r.WithContext(WithContext(r.Context(), info)))
		})
	}
}
