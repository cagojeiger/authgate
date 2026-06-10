package middleware

import "net/http"

// contentSecurityPolicy is tuned for authgate's served HTML (the device-entry,
// device-approve, result and error pages under internal/pages/templates).
// Those pages use exactly one inline <style> block plus Google Fonts and carry
// no scripts, no event-handler attributes and no <img> tags. The policy:
//   - default-src 'none' denies everything not explicitly re-allowed, so
//     script-src inherits 'none' — no inline or remote JS can ever execute.
//   - style-src allows the inline <style> ('unsafe-inline') and the Google
//     Fonts stylesheet; font-src allows the gstatic font files.
//   - frame-ancestors 'none' and base-uri 'none' block clickjacking and <base>
//     hijacking. The JSON API responses also receive this header harmlessly —
//     browsers load no subresources from a JSON body.
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

// SecurityHeaders returns middleware that sets baseline security response
// headers on every response. It is wired as the OUTERMOST middleware so the
// headers are present on error responses and CORS preflight replies too. The
// headers are set before the inner handler runs, so they land in the header map
// regardless of which downstream handler commits the response.
//
// devMode gates Strict-Transport-Security: in dev the server runs over plain
// HTTP (and PUBLIC_URL is http://), where an HSTS header would be ignored by
// browsers anyway and only confuse local testing.
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
