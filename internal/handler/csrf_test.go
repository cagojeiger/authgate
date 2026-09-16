package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// csrf-unit-001: outside dev the cookie carries __Host-, which a sibling
// subdomain cannot write; in dev the prefix is dropped because it requires
// Secure and Chrome/Safari ignore such a cookie over http on localhost.
func TestCSRFCookieName(t *testing.T) {
	if got := csrfCookieName(logoutCSRFCookie, false); got != "__Host-end_session_csrf" {
		t.Errorf("prod name = %q, want __Host-end_session_csrf", got)
	}
	if got := csrfCookieName(deviceCSRFCookie, false); got != "__Host-device_csrf" {
		t.Errorf("prod name = %q, want __Host-device_csrf", got)
	}
	if got := csrfCookieName(logoutCSRFCookie, true); got != "end_session_csrf" {
		t.Errorf("dev name = %q, want end_session_csrf", got)
	}
}

// csrf-unit-002: the set cookie satisfies every __Host- requirement, and the
// clearing cookie matches it attribute for attribute.
func TestSetAndClearCSRFCookie(t *testing.T) {
	for _, devMode := range []bool{false, true} {
		set := httptest.NewRecorder()
		setCSRFCookie(set, deviceCSRFCookie, "tok", devMode)
		clear := httptest.NewRecorder()
		clearCSRFCookie(clear, deviceCSRFCookie, devMode)

		c := set.Result().Cookies()[0]
		if c.Path != "/" || c.Domain != "" || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
			t.Errorf("devMode=%v cookie = %+v, want Path=/, no Domain, HttpOnly, Strict", devMode, c)
		}
		if c.Secure == devMode {
			t.Errorf("devMode=%v Secure = %v", devMode, c.Secure)
		}
		if strings.HasPrefix(c.Name, "__Host-") && !c.Secure {
			t.Errorf("__Host- cookie without Secure is ignored by browsers: %+v", c)
		}
		d := clear.Result().Cookies()[0]
		if d.Name != c.Name || d.Path != c.Path || d.Secure != c.Secure || d.HttpOnly != c.HttpOnly || d.SameSite != c.SameSite || d.MaxAge >= 0 {
			t.Errorf("clearing cookie %+v does not match %+v", d, c)
		}
	}
}

// csrf-unit-003: in production the unprefixed cookie a sibling subdomain can
// write is not read back — accepting both names would hand the attacker the
// double-submit bypass the prefix exists to close.
func TestValidCSRFToken_IgnoresUnprefixedCookieInProd(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/device/approve", nil)
	r.AddCookie(&http.Cookie{Name: deviceCSRFCookie, Value: "attacker"})
	if validCSRFToken(r, deviceCSRFCookie, "attacker", false) {
		t.Error("prod accepted the unprefixed cookie")
	}

	ok := httptest.NewRequest(http.MethodPost, "/device/approve", nil)
	ok.AddCookie(&http.Cookie{Name: csrfCookieName(deviceCSRFCookie, false), Value: "real"})
	if !validCSRFToken(ok, deviceCSRFCookie, "real", false) {
		t.Error("prod rejected the prefixed cookie")
	}
	if validCSRFToken(ok, deviceCSRFCookie, "", false) {
		t.Error("an empty form token passed")
	}
	if validCSRFToken(ok, deviceCSRFCookie, "other", false) {
		t.Error("a mismatched form token passed")
	}
}

// csrf-unit-004: Sec-Fetch-Site separates a sibling subdomain ("same-site")
// from authgate's own page ("same-origin"); Origin covers browsers that do not
// send Fetch Metadata.
func TestSameOriginPost(t *testing.T) {
	cases := []struct {
		name    string
		site    string
		origin  string
		devMode bool
		want    bool
	}{
		{name: "own page", site: "same-origin", want: true},
		{name: "sibling subdomain", site: "same-site", want: false},
		{name: "cross-site", site: "cross-site", want: false},
		{name: "user typed", site: "none", want: false},
		{name: "matching origin", origin: "https://example.com", want: true},
		{name: "sibling origin", origin: "https://evil.example.com", want: false},
		{name: "origin null", origin: "null", want: false},
		{name: "scheme downgrade", origin: "http://example.com", want: false},
		{name: "dev http origin", origin: "http://example.com", devMode: true, want: true},
		{name: "no browser signal", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://example.com/device/approve", nil)
			r.Host = "example.com"
			if tc.site != "" {
				r.Header.Set("Sec-Fetch-Site", tc.site)
			}
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if got := sameOriginPost(r, tc.devMode); got != tc.want {
				t.Errorf("sameOriginPost = %v, want %v", got, tc.want)
			}
		})
	}
}

// csrf-unit-005: a sibling subdomain that has written the CSRF cookie still
// cannot approve a device, because its POST is not same-origin.
func TestDeviceApprove_RefusesSiblingSubdomainPost(t *testing.T) {
	h := newTestDeviceHandler() // devMode=true: cookie name is unprefixed here
	form := strings.NewReader("csrf_token=tok&user_code=ABCD-EFGH&action=approve")
	r := httptest.NewRequest(http.MethodPost, "/device/approve", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-site")
	r.AddCookie(&http.Cookie{Name: deviceCSRFCookie, Value: "tok"})

	rec := httptest.NewRecorder()
	h.HandleDeviceApprove(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}
