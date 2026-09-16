package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/storage"
)

func maxAgeStore(t *testing.T, maxAge *uint, prompt []string, channel string, sessionAge time.Duration, completed *bool) *fakeLoginStore {
	t.Helper()
	store := promptTestStore(t, prompt, "active", channel, completed)
	store.sessionAuthTime = time.Now().Add(-sessionAge)
	inner := store.getAuthRequestModelFn
	store.getAuthRequestModelFn = func(ctx context.Context, id string) (*storage.AuthRequestModel, error) {
		authReq, err := inner(ctx, id)
		if err != nil {
			return nil, err
		}
		authReq.MaxAge = maxAge
		return authReq, nil
	}
	return store
}

func maxAgeOf(seconds uint) *uint { return &seconds }

// max-age-001: a session younger than max_age is still reused.
func TestMaxAge_FreshSessionIsReused(t *testing.T) {
	for _, ch := range promptChannels {
		t.Run(ch.channel, func(t *testing.T) {
			completed := false
			store := maxAgeStore(t, maxAgeOf(3600), nil, ch.channel, 10*time.Minute, &completed)
			if result := ch.login(store); result.Action != ActionAutoApprove {
				t.Fatalf("action = %v, want ActionAutoApprove", result.Action)
			}
			if !completed {
				t.Error("the auth request was not completed")
			}
		})
	}
}

// max-age-002: a session older than max_age is not reused; the user is sent
// upstream to authenticate again (OIDC Core 3.1.2.1).
func TestMaxAge_StaleSessionGoesUpstream(t *testing.T) {
	for _, ch := range promptChannels {
		t.Run(ch.channel, func(t *testing.T) {
			completed := false
			store := maxAgeStore(t, maxAgeOf(300), nil, ch.channel, 2*time.Hour, &completed)
			result := ch.login(store)
			if result.Action != ActionRedirectToIdP {
				t.Fatalf("action = %v, want ActionRedirectToIdP", result.Action)
			}
			if result.UpstreamPrompt != upstreamPromptSelectAccount {
				t.Errorf("upstream prompt = %q, want %q", result.UpstreamPrompt, upstreamPromptSelectAccount)
			}
			if completed {
				t.Error("a session too old for max_age still completed the request")
			}
		})
	}
}

// max-age-003: max_age=0 — what zitadel derives from prompt=login — refuses
// even a session created a moment ago.
func TestMaxAge_ZeroRefusesEverySession(t *testing.T) {
	for _, ch := range promptChannels {
		t.Run(ch.channel, func(t *testing.T) {
			completed := false
			store := maxAgeStore(t, maxAgeOf(0), nil, ch.channel, time.Second, &completed)
			if result := ch.login(store); result.Action != ActionRedirectToIdP {
				t.Fatalf("action = %v, want ActionRedirectToIdP", result.Action)
			}
			if completed {
				t.Error("max_age=0 reused a session")
			}
		})
	}
}

// max-age-004: with prompt=none there is no one to ask, so a session that
// cannot satisfy max_age ends the request with login_required (Core 3.1.2.6)
// instead of a silent stale answer.
func TestMaxAge_StaleSessionWithPromptNone_LoginRequired(t *testing.T) {
	for _, ch := range promptChannels {
		t.Run(ch.channel, func(t *testing.T) {
			completed := false
			store := maxAgeStore(t, maxAgeOf(60), []string{"none"}, ch.channel, time.Hour, &completed)
			result := ch.login(store)
			if result.Action != ActionRedirectToClient {
				t.Fatalf("action = %v, want ActionRedirectToClient", result.Action)
			}
			if !strings.Contains(result.RedirectURL, "error=login_required") {
				t.Errorf("redirect = %q, want error=login_required", result.RedirectURL)
			}
			if completed {
				t.Error("prompt=none completed a request whose session was too old")
			}
		})
	}
}

// max-age-005: a request without max_age is unaffected, however old the
// session is.
func TestMaxAge_AbsentNeverRefuses(t *testing.T) {
	for _, ch := range promptChannels {
		t.Run(ch.channel, func(t *testing.T) {
			completed := false
			store := maxAgeStore(t, nil, nil, ch.channel, 30*24*time.Hour, &completed)
			if result := ch.login(store); result.Action != ActionAutoApprove {
				t.Fatalf("action = %v, want ActionAutoApprove", result.Action)
			}
		})
	}
}

// max-age-006: reusing a session records auth_time as when that session was
// created — the last time the user actually authenticated upstream — not the
// moment the request was completed (OIDC Core 2).
func TestReusedSession_AuthTimeIsTheSessionsOwn(t *testing.T) {
	for _, ch := range promptChannels {
		t.Run(ch.channel, func(t *testing.T) {
			completed := false
			store := maxAgeStore(t, nil, nil, ch.channel, 6*time.Hour, &completed)
			if result := ch.login(store); result.Action != ActionAutoApprove {
				t.Fatalf("action = %v, want ActionAutoApprove", result.Action)
			}
			if store.completedAuthTime.IsZero() {
				t.Fatal("auth_time was left for storage to default to now; a reused session must carry its own")
			}
			if drift := store.completedAuthTime.Sub(store.sessionAuthTime); drift > time.Second || drift < -time.Second {
				t.Errorf("auth_time = %v, want the session's creation time %v", store.completedAuthTime, store.sessionAuthTime)
			}
		})
	}
}

// max-age-007: an RP may ask for a max_age larger than a time.Duration can
// hold. Multiplying it into a Duration wraps negative and would refuse every
// session — the opposite of what such a request means.
func TestMaxAge_HugeValueDoesNotWrap(t *testing.T) {
	authReq := &storage.AuthRequestModel{MaxAge: maxAgeOf(1 << 62)}
	now := time.Now()
	if sessionTooOldForMaxAge(authReq, now.Add(-365*24*time.Hour), now) {
		t.Error("a year-old session was refused by a max_age of 2^62 seconds")
	}
}

// max-age-008: a clock that steps backwards must not be read as "older than
// max_age".
func TestMaxAge_FutureAuthTimeIsNotStale(t *testing.T) {
	authReq := &storage.AuthRequestModel{MaxAge: maxAgeOf(60)}
	now := time.Now()
	if sessionTooOldForMaxAge(authReq, now.Add(time.Minute), now) {
		t.Error("a session created in the future was treated as stale")
	}
}

// max-age-009: prompt=none has nowhere to send the user, so a vanished session
// ends the request with login_required rather than an upstream redirect.
func TestMaxAge_SessionLookupFailsUnderPromptNone_LoginRequired(t *testing.T) {
	for _, ch := range promptChannels {
		t.Run(ch.channel, func(t *testing.T) {
			completed := false
			store := maxAgeStore(t, maxAgeOf(60), []string{"none"}, ch.channel, time.Minute, &completed)
			store.sessionAuthTimeFn = func(context.Context, string) (time.Time, error) {
				return time.Time{}, storage.ErrNotFound
			}
			result := ch.login(store)
			if result.Action == ActionRedirectToIdP {
				t.Fatal("prompt=none was sent to the upstream IdP")
			}
			if result.Action != ActionRedirectToClient || !strings.Contains(result.RedirectURL, "error=login_required") {
				t.Fatalf("action = %v, redirect = %q; want login_required", result.Action, result.RedirectURL)
			}
		})
	}
}
