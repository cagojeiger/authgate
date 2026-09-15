package middleware

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/kangheeyong/authgate/internal/logctx"
)

// logThroughContext stands in for zitadel/oidc: it logs with the request
// context and records what it could still read from the form.
func logThroughContext(buf *bytes.Buffer, formSeen *url.Values) http.Handler {
	logger := slog.New(logctx.NewHandler(slog.NewTextHandler(buf, nil)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil && formSeen != nil {
			*formSeen = r.PostForm
		}
		logger.WarnContext(r.Context(), "request error")
		w.WriteHeader(http.StatusBadRequest)
	})
}

func postForm(target string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestTokenLogContext_FormClientAndGrantType(t *testing.T) {
	var buf bytes.Buffer
	var formSeen url.Values
	h := TokenLogContext(logThroughContext(&buf, &formSeen))

	h.ServeHTTP(httptest.NewRecorder(), postForm("/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"https://claude.ai/oauth/claude-code-client-metadata"},
		"refresh_token": {"rt-secret-value"},
	}))

	got := buf.String()
	for _, want := range []string{"client_id=https://claude.ai/oauth/claude-code-client-metadata", "grant_type=refresh_token"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log line %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "rt-secret-value") {
		t.Fatalf("refresh token leaked into the log: %q", got)
	}
	// The downstream handler must still read the whole body.
	if formSeen.Get("refresh_token") != "rt-secret-value" {
		t.Fatalf("downstream handler lost the form body, got %v", formSeen)
	}
}

func TestTokenLogContext_BasicAuthClientIDWithoutSecret(t *testing.T) {
	var buf bytes.Buffer
	h := TokenLogContext(logThroughContext(&buf, nil))

	req := postForm("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {"c"}})
	// RFC 6749 §2.3.1: the Basic credentials are form-encoded first.
	req.SetBasicAuth(url.QueryEscape("cloudflare access"), "super-secret")
	h.ServeHTTP(httptest.NewRecorder(), req)

	got := buf.String()
	if !strings.Contains(got, `client_id="cloudflare access"`) {
		t.Fatalf("log line %q is missing the decoded Basic client_id", got)
	}
	if strings.Contains(got, "super-secret") {
		t.Fatalf("client secret leaked into the log: %q", got)
	}
}

func TestTokenLogContext_NoIdentifiersAddsNothing(t *testing.T) {
	var buf bytes.Buffer
	h := TokenLogContext(logThroughContext(&buf, nil))

	h.ServeHTTP(httptest.NewRecorder(), postForm("/oauth/token", url.Values{}))

	if got := buf.String(); strings.Contains(got, "client_id") || strings.Contains(got, "grant_type") {
		t.Fatalf("expected no identifiers, got %q", got)
	}
}

func TestRequestIDMiddleware_AddsRequestIDAndPathToLogs(t *testing.T) {
	var buf bytes.Buffer
	h := RequestIDMiddleware(logThroughContext(&buf, nil))

	req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=x&state=secret-state", nil)
	req.Header.Set("X-Request-ID", "abc-123")
	h.ServeHTTP(httptest.NewRecorder(), req)

	got := buf.String()
	for _, want := range []string{"request_id=abc-123", "path=/authorize"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log line %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "secret-state") {
		t.Fatalf("query string leaked into the log: %q", got)
	}
}

// Downstream handlers must see a malformed body exactly as before: ParseForm
// reports the error only on its first call, so the middleware must not be the
// one making it.
func TestTokenLogContext_MalformedBodyErrorReachesHandler(t *testing.T) {
	var parseErr error
	h := TokenLogContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parseErr = r.ParseForm()
	}))

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=refresh_token&client_id=gitea&bad=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if parseErr == nil {
		t.Fatal("downstream ParseForm did not report the malformed body")
	}
}

// A body longer than the peek window must still arrive whole.
func TestTokenLogContext_LongBodyArrivesWhole(t *testing.T) {
	var seen url.Values
	h := TokenLogContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		seen = r.PostForm
	}))

	padding := strings.Repeat("a", tokenLogBodyPeekBytes)
	body := url.Values{"client_id": {"gitea"}, "padding": {padding}, "tail": {"kept"}}.Encode()
	h.ServeHTTP(httptest.NewRecorder(), postForm("/oauth/token", mustParseQuery(t, body)))

	if seen.Get("tail") != "kept" || len(seen.Get("padding")) != len(padding) {
		t.Fatalf("body was cut: tail=%q padding=%d", seen.Get("tail"), len(seen.Get("padding")))
	}
}

func mustParseQuery(t *testing.T, s string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(s)
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	return v
}

func TestTokenLogContext_TruncatesLongValues(t *testing.T) {
	var buf bytes.Buffer
	h := TokenLogContext(logThroughContext(&buf, nil))

	h.ServeHTTP(httptest.NewRecorder(), postForm("/oauth/token", url.Values{
		"client_id":  {strings.Repeat("x", 1<<20)},
		"grant_type": {"refresh_token"},
	}))

	got := buf.String()
	if len(got) > 2*maxLogValueBytes+256 {
		t.Fatalf("log line is %d bytes; a client-supplied value was not truncated", len(got))
	}
	if !strings.Contains(got, "…(truncated)") {
		t.Fatalf("truncated value is not marked: %q", got)
	}
}

func TestTruncateLogValue_KeepsRuneBoundary(t *testing.T) {
	s := strings.Repeat("a", maxLogValueBytes-1) + "한글"
	got := truncateLogValue(s)
	if !utf8.ValidString(got) {
		t.Fatalf("truncation split a rune: %q", got)
	}
	if !strings.HasSuffix(got, "…(truncated)") {
		t.Fatalf("missing truncation marker: %q", got)
	}
}

// shortBody behaves like net/http's server body when the client sends fewer
// bytes than its Content-Length: the missing bytes surface once as
// io.ErrUnexpectedEOF, and every later read returns io.EOF.
type shortBody struct {
	data   *strings.Reader
	failed bool
}

func (b *shortBody) Read(p []byte) (int, error) {
	if b.data.Len() > 0 {
		return b.data.Read(p)
	}
	if !b.failed {
		b.failed = true
		return 0, io.ErrUnexpectedEOF
	}
	return 0, io.EOF
}

func (b *shortBody) Close() error { return nil }

// A body the client cut short must still fail downstream. Otherwise a dropped
// connection would run the grant on a partial form: the refresh token rotates,
// the client never receives the new one, and its retry is treated as reuse.
func TestTokenLogContext_TruncatedBodyStillFailsDownstream(t *testing.T) {
	var parseErr error
	h := TokenLogContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parseErr = r.ParseForm()
	}))

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = &shortBody{data: strings.NewReader("grant_type=refresh_token&refresh_token=abc")}
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !errors.Is(parseErr, io.ErrUnexpectedEOF) {
		t.Fatalf("downstream ParseForm err = %v, want io.ErrUnexpectedEOF", parseErr)
	}
}
