package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/google/uuid"

	"github.com/kangheeyong/authgate/internal/logctx"
)

type contextKey string

const requestIDKey contextKey = "request_id"

// validRequestID matches alphanumeric characters, hyphens, and underscores — max 64 chars.
var validRequestID = regexp.MustCompile(`^[a-zA-Z0-9\-_]{1,64}$`)

// RequestIDMiddleware reads X-Request-ID from the incoming request (validating it),
// or generates a new UUID if absent or invalid. It stores the ID in the request
// context and echoes it back as an X-Request-ID response header. The ID and the
// request path are also attached to every log record written with the request
// context, so a server log line can be matched to the ingress access log, which
// records the same X-Request-ID.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !validRequestID.MatchString(id) {
			id = uuid.New().String()
		}

		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		ctx = logctx.With(ctx, slog.String("request_id", id), slog.String("path", r.URL.Path))
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// RequestIDFromContext returns the request ID stored in ctx, or an empty string
// if none is present.
func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}
