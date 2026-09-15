package middleware

import (
	"bytes"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/kangheeyong/authgate/internal/logctx"
)

const (
	// tokenLogBodyPeekBytes bounds how much of a token request body is read to
	// find client_id and grant_type. Token requests are a few hundred bytes.
	tokenLogBodyPeekBytes = 64 << 10
	// maxLogValueBytes bounds a client-supplied value in a log line, so an
	// unauthenticated request cannot write megabyte lines.
	maxLogValueBytes = 256
)

// TokenLogContext attaches client_id and grant_type to the log context of a
// token-style request, so the "request error" lines zitadel/oidc writes for a
// failed grant say which client failed and how.
//
// client_id comes from the form, or from the HTTP Basic username when the
// client authenticates with client_secret_basic (RFC 6749 §2.3.1 form-encodes
// it). The Basic password is never read.
//
// The request itself is left exactly as it arrived: the body is peeked and
// restored rather than parsed with r.ParseForm. ParseForm reports a malformed
// body only on its first call, so parsing here would hide that error from the
// handlers downstream and change how they answer bad input.
func TokenLogContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		form := peekForm(r)
		var attrs []slog.Attr
		if clientID := tokenRequestClientID(r, form); clientID != "" {
			attrs = append(attrs, slog.String("client_id", truncateLogValue(clientID)))
		}
		if grantType := strings.TrimSpace(form.Get("grant_type")); grantType != "" {
			attrs = append(attrs, slog.String("grant_type", truncateLogValue(grantType)))
		}
		if len(attrs) > 0 {
			r = r.WithContext(logctx.With(r.Context(), attrs...))
		}
		next.ServeHTTP(w, r)
	})
}

// peekForm decodes the start of a form-encoded POST body for logging and puts
// the bytes back so the body reads the same downstream. A decoding error only
// means fewer attributes; the values decoded before it are still returned.
func peekForm(r *http.Request) url.Values {
	if r.Method != http.MethodPost || r.Body == nil {
		return url.Values{}
	}
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/x-www-form-urlencoded" {
		return url.Values{}
	}
	peeked, err := io.ReadAll(io.LimitReader(r.Body, tokenLogBodyPeekBytes))
	rest := r.Body
	if err != nil {
		// Replay the read error after the peeked bytes. net/http reports a body
		// cut short (io.ErrUnexpectedEOF) only once and then returns io.EOF, so
		// reading on from the original body would hand the handler a partial
		// body that looks complete.
		rest = struct {
			io.Reader
			io.Closer
		}{errReader{err}, r.Body}
	}
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(peeked), rest), r.Body}
	if err != nil {
		return url.Values{}
	}
	form, _ := url.ParseQuery(string(peeked))
	return form
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func tokenRequestClientID(r *http.Request, form url.Values) string {
	if clientID := strings.TrimSpace(form.Get("client_id")); clientID != "" {
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

// truncateLogValue shortens s to at most maxLogValueBytes on a rune boundary and
// marks the cut.
func truncateLogValue(s string) string {
	if len(s) <= maxLogValueBytes {
		return s
	}
	cut := maxLogValueBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…(truncated)"
}
