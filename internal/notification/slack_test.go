package notification

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSlackClientPost_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	err := NewSlackClient(srv.URL, srv.Client()).Post(context.Background(), "hello")
	rateErr, ok := err.(*RateLimitError)
	if !ok {
		t.Fatalf("err = %T %[1]v, want *RateLimitError", err)
	}
	if rateErr.RetryAfter != 7*time.Second {
		t.Fatalf("RetryAfter = %v, want 7s", rateErr.RetryAfter)
	}
}
