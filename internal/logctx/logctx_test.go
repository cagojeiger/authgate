package logctx

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func newTestLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(NewHandler(slog.NewTextHandler(buf, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})))
}

func TestHandler_AddsContextAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	ctx := With(context.Background(), slog.String("request_id", "r-1"))
	ctx = With(ctx, slog.String("client_id", "cloudflare-access"))
	logger.WarnContext(ctx, "request error", "oidc_error", "invalid_grant")

	got := buf.String()
	for _, want := range []string{"request_id=r-1", "client_id=cloudflare-access", "oidc_error=invalid_grant"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log line %q is missing %q", got, want)
		}
	}
}

func TestHandler_NoContextAttrsLeavesRecordAlone(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	logger.InfoContext(context.Background(), "token cleanup (revoked)", "deleted", 1)

	if got, want := strings.TrimSpace(buf.String()), `level=INFO msg="token cleanup (revoked)" deleted=1`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A context attribute must not leak into records written with a different
// context through the same logger.
func TestHandler_AttrsDoNotLeakAcrossContexts(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	logger.InfoContext(With(context.Background(), slog.String("client_id", "a")), "first")
	buf.Reset()
	logger.InfoContext(context.Background(), "second")

	if strings.Contains(buf.String(), "client_id") {
		t.Fatalf("attribute leaked into an unrelated record: %q", buf.String())
	}
}

func TestHandler_KeepsWithAttrsAndGroups(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf).With("component", "cleanup").WithGroup("job")

	logger.InfoContext(With(context.Background(), slog.String("request_id", "r-2")), "done", "n", 3)

	got := buf.String()
	for _, want := range []string{"component=cleanup", "job.n=3", "job.request_id=r-2"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log line %q is missing %q", got, want)
		}
	}
}

func TestWith_NoAttrsReturnsSameContext(t *testing.T) {
	ctx := context.Background()
	if With(ctx) != ctx {
		t.Fatal("With without attributes should return the context unchanged")
	}
}
