package clientinfo

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mustParseTrusted is a tiny test helper so each test case can declare a
// trusted-CIDR list inline without repeating ParseTrustedProxies error checks.
func mustParseTrusted(t *testing.T, spec string) []*net.IPNet {
	t.Helper()
	nets, err := ParseTrustedProxies(spec)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%q) error: %v", spec, err)
	}
	return nets
}

func TestExtract_NoTrust_UsesRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:51234"
	got := Extract(r, nil)
	if got.IP != "203.0.113.5" {
		t.Fatalf("IP = %q, want 203.0.113.5", got.IP)
	}
}

// Spoof prevention: with no trusted proxies the X-Forwarded-For header must be
// ignored even if a malicious client sets it.
func TestExtract_NoTrust_IgnoresXFF(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:51234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	got := Extract(r, nil)
	if got.IP != "203.0.113.5" {
		t.Fatalf("IP = %q, want 203.0.113.5 (XFF ignored without trust)", got.IP)
	}
}

func TestExtract_Trust_UsesXFFLeftmost(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.2.54:443"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "1.2.3.4" {
		t.Fatalf("IP = %q, want 1.2.3.4", got.IP)
	}
}

func TestExtract_Trust_NoXFF_FallsBackToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.2.54:443"
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "10.244.2.54" {
		t.Fatalf("IP = %q, want 10.244.2.54", got.IP)
	}
}

// Spoof prevention: the trust list is non-empty but the actual hop comes from
// outside that list — the XFF header must be ignored.
func TestExtract_Trust_RemoteAddrOutsideCIDR_IgnoresXFF(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "198.51.100.7:51234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "198.51.100.7" {
		t.Fatalf("IP = %q, want 198.51.100.7 (untrusted hop must not honor XFF)", got.IP)
	}
}

func TestExtract_PortStripped_IPv4(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:5678"
	got := Extract(r, nil)
	if got.IP != "1.2.3.4" {
		t.Fatalf("IP = %q, want 1.2.3.4", got.IP)
	}
}

func TestExtract_PortStripped_IPv6(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bracketed-with-port", "[2001:db8::1]:5678", "2001:db8::1"},
		{"loopback-with-port", "[::1]:1234", "::1"},
		{"bare", "::1", "::1"},
		{"bracketed-without-port", "[::1]", "::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.in
			got := Extract(r, nil)
			if got.IP != tc.want {
				t.Fatalf("IP for %q = %q, want %q", tc.in, got.IP, tc.want)
			}
		})
	}
}

func TestExtract_XFFMultipleHops_TakesLeftmost(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.0.5:443"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8, 9.0.1.2")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "1.2.3.4" {
		t.Fatalf("IP = %q, want leftmost 1.2.3.4", got.IP)
	}
}

func TestExtract_XFFWhitespaceTrimmed(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.0.5:443"
	r.Header.Set("X-Forwarded-For", "  1.2.3.4  , 5.6.7.8")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "1.2.3.4" {
		t.Fatalf("IP = %q, want 1.2.3.4", got.IP)
	}
}

func TestExtract_UnparseableIP_EmptyResult(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "garbage"
	got := Extract(r, nil)
	if got.IP != "" {
		t.Fatalf("IP = %q, want empty for unparseable input", got.IP)
	}
}

func TestExtract_UserAgentPassedThrough(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:443"
	r.Header.Set("User-Agent", "Mozilla/5.0 (probe)")
	got := Extract(r, nil)
	if got.UserAgent != "Mozilla/5.0 (probe)" {
		t.Fatalf("UA = %q, want Mozilla/5.0 (probe)", got.UserAgent)
	}
}

// Garbage XFF (header present but unparseable) must fall back to the trusted
// hop. Without this guarantee a malformed proxy could silently zero out the
// audit IP for trusted requests.
func TestExtract_Trust_GarbageXFF_FallsBackToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.0.5:443"
	r.Header.Set("X-Forwarded-For", "not-an-ip")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "10.244.0.5" {
		t.Fatalf("IP = %q, want 10.244.0.5 (garbage XFF must fall back to trusted hop)", got.IP)
	}
}

// IPv6 leftmost in XFF must round-trip correctly through normalization.
// strings.Cut on the comma is safe because IPv6 addresses don't contain
// commas, but we exercise it explicitly to lock the contract.
func TestExtract_Trust_XFFIPv6Leftmost(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.0.5:443"
	r.Header.Set("X-Forwarded-For", "2001:db8::1, 5.6.7.8")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "2001:db8::1" {
		t.Fatalf("IP = %q, want 2001:db8::1", got.IP)
	}
}

func TestExtract_EmptyXFF_FallsBackToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.0.5:443"
	r.Header.Set("X-Forwarded-For", "")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "10.244.0.5" {
		t.Fatalf("IP = %q, want 10.244.0.5", got.IP)
	}
}

func TestParseTrustedProxies_Empty_NilNil(t *testing.T) {
	got, err := ParseTrustedProxies("")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != nil {
		t.Fatalf("got = %v, want nil", got)
	}
}

func TestParseTrustedProxies_Multiple(t *testing.T) {
	got, err := ParseTrustedProxies("10.0.0.0/8, 192.168.0.0/16")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].String() != "10.0.0.0/8" || got[1].String() != "192.168.0.0/16" {
		t.Fatalf("got = %v", got)
	}
}

func TestParseTrustedProxies_WhitespaceOnly_Skipped(t *testing.T) {
	got, err := ParseTrustedProxies("10.0.0.0/8, , 192.168.0.0/16")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (whitespace-only entry must be skipped)", len(got))
	}
}

func TestParseTrustedProxies_Invalid_Error(t *testing.T) {
	cases := []string{
		"not-a-cidr",
		"10.0.0.0",     // bare IP, no /mask — must be rejected
		"10.0.0.0/40",  // mask out of range
		"::/-1",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := ParseTrustedProxies(in); err == nil {
				t.Fatalf("ParseTrustedProxies(%q) err = nil, want non-nil", in)
			}
		})
	}
}

func TestMiddleware_AttachesContext(t *testing.T) {
	trusted := mustParseTrusted(t, "10.244.0.0/16")
	var got Info
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = FromContext(r.Context())
	})
	h := Middleware(trusted)(inner)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.244.2.54:443"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("User-Agent", "probe/1.0")

	h.ServeHTTP(httptest.NewRecorder(), req)

	if got.IP != "1.2.3.4" {
		t.Fatalf("ctx IP = %q, want 1.2.3.4", got.IP)
	}
	if got.UserAgent != "probe/1.0" {
		t.Fatalf("ctx UA = %q, want probe/1.0", got.UserAgent)
	}
}

func TestFromContext_Absent_ReturnsZeroInfo(t *testing.T) {
	if got := FromContext(context.Background()); got != (Info{}) {
		t.Fatalf("FromContext(empty) = %#v, want zero", got)
	}
	// nil ctx must not panic and must return zero.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FromContext(nil) panicked: %v", r)
		}
	}()
	if got := FromContext(nil); got != (Info{}) {
		t.Fatalf("FromContext(nil) = %#v, want zero", got)
	}
}
