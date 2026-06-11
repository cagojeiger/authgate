package middleware

import "net/http"

// contentSecurityPolicy matches authgate's static HTML (internal/pages/templates):
// no scripts, one inline <style> block, Google Fonts only. See
// docs/security/002-http-security-headers.md for the full rationale.
const contentSecurityPolicy = "default-src 'none'; " +
	"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
	"font-src https://fonts.gstatic.com; " +
	"img-src 'self' data:; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'"

// strictTransportSecurity is emitted only outside dev mode (i.e. when served
// over HTTPS). One year, no includeSubDomains: authgate is a dedicated host and
// should not silently force HTTPS onto sibling subdomains the operator may not
// control. Operators who want a stronger policy can layer it at the proxy.
const strictTransportSecurity = "max-age=31536000"

// SecurityHeaders sets baseline security headers on every response. Wire it as
// the OUTERMOST middleware so they reach error and CORS-preflight replies too.
// devMode omits HSTS (dev serves plain HTTP, where browsers ignore it anyway).
func SecurityHeaders(devMode bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", contentSecurityPolicy)
			if !devMode {
				h.Set("Strict-Transport-Security", strictTransportSecurity)
			}
			next.ServeHTTP(w, r)
		})
	}
}
