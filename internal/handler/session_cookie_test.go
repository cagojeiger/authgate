package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// session-cookie-001: the session cookie must be Lax.
//
// Strict is the tempting choice and it was what shipped, but it made the
// device flow impossible to complete in Safari. Each login ends with the IdP
// redirecting to a callback that mints the session and redirects on to
// /device?user_code=…; WebKit judges that last hop by the whole redirect
// chain, which the IdP started cross-site, so it withholds a Strict cookie.
// The device page saw no session, bounced back to the IdP, and the user
// looped. Chromium sends the cookie there, so this failed on one engine only.
//
// If this assertion is ever flipped back to Strict, that regression returns.
func TestSetSessionCookie_IsLaxSoTheIdPRedirectSurvives(t *testing.T) {
	rec := httptest.NewRecorder()
	setSessionCookie(rec, "session-value", false)

	c := findCookie(t, rec.Result().Cookies(), sessionCookieName)

	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax: Strict is dropped on the hop back from the IdP", c.SameSite)
	}
	if !c.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if !c.Secure {
		t.Error("Secure = false, want true outside dev mode")
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want /", c.Path)
	}
}

// session-cookie-002: dev mode is the only way to drop Secure.
func TestSetSessionCookie_SecureOnlyRelaxedInDevMode(t *testing.T) {
	rec := httptest.NewRecorder()
	setSessionCookie(rec, "session-value", true)

	if findCookie(t, rec.Result().Cookies(), sessionCookieName).Secure {
		t.Error("Secure = true in dev mode, want false for plain-HTTP localhost")
	}
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cookie %q was not set", name)
	return nil
}
