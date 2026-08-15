package middleware

import (
	"net/http"
	"net/url"
)

// AuthorizationResponseIssuer adds the RFC 9207 issuer identifier to final
// OAuth authorization responses. Intermediate AuthGate redirects are unchanged.
func AuthorizationResponseIssuer(issuer string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&issuerResponseWriter{ResponseWriter: w, issuer: issuer}, r)
	})
}

type issuerResponseWriter struct {
	http.ResponseWriter
	issuer string
}

func (w *issuerResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *issuerResponseWriter) WriteHeader(statusCode int) {
	if statusCode >= http.StatusMultipleChoices && statusCode < http.StatusBadRequest {
		if location := w.Header().Get("Location"); location != "" {
			w.Header().Set("Location", authorizationResponseLocation(location, w.issuer))
		}
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func authorizationResponseLocation(location, issuer string) string {
	target, err := url.Parse(location)
	if err != nil || !target.IsAbs() {
		return location
	}
	query := target.Query()
	if !query.Has("code") && !query.Has("error") {
		return location
	}
	query.Set("iss", issuer)
	target.RawQuery = query.Encode()
	return target.String()
}
