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

// Rightmost-untrusted walk: with no entries inside the trusted CIDR, the
// rightmost entry is the immediate proxy upstream we trust by topology
// (the IP appended by the closest proxy), which is the original client.
func TestExtract_Trust_UsesXFFRightmostUntrusted(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.2.54:443"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "5.6.7.8" {
		t.Fatalf("IP = %q, want 5.6.7.8 (rightmost untrusted)", got.IP)
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

func TestExtract_XFFMultipleHops_TakesRightmostUntrusted(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.0.5:443"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8, 9.0.1.2")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "9.0.1.2" {
		t.Fatalf("IP = %q, want rightmost untrusted 9.0.1.2", got.IP)
	}
}

func TestExtract_XFFWhitespaceTrimmed(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.0.5:443"
	r.Header.Set("X-Forwarded-For", "1.2.3.4 ,  5.6.7.8  ")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "5.6.7.8" {
		t.Fatalf("IP = %q, want 5.6.7.8", got.IP)
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

// IPv6 in XFF must round-trip correctly through normalization. IPv6 entries
// don't contain commas so the simple comma split is safe, but we exercise
// it explicitly to lock the contract. The rightmost-untrusted walk picks
// 5.6.7.8 (the rightmost entry, neither in the trusted CIDR).
func TestExtract_Trust_XFFIPv6Mixed(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.0.5:443"
	r.Header.Set("X-Forwarded-For", "2001:db8::1, 5.6.7.8")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "5.6.7.8" {
		t.Fatalf("IP = %q, want 5.6.7.8", got.IP)
	}
}

// IPv6 standalone in a single-entry XFF must be returned by the rightmost
// walk when it is not itself inside the trusted CIDR.
func TestExtract_Trust_XFFIPv6Standalone(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.0.5:443"
	r.Header.Set("X-Forwarded-For", "2001:db8::1")
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

// X-Envoy-External-Address is the istio/envoy ingress's spoof-resistant
// single-IP header; when present and the request hop is trusted, it wins
// over X-Forwarded-For walking entirely.
func TestExtract_Trust_XEnvoyExternalAddress_Used(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.2.54:443"
	r.Header.Set("X-Envoy-External-Address", "175.210.118.204")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "175.210.118.204" {
		t.Fatalf("IP = %q, want 175.210.118.204", got.IP)
	}
}

// Both headers present: X-Envoy-External-Address wins because envoy
// guarantees it (overwrites incoming) whereas XFF leftmost is freely
// settable by the client.
func TestExtract_Trust_XEnvoyExternalAddress_TakesPrecedenceOverXFF(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.2.54:443"
	r.Header.Set("X-Envoy-External-Address", "175.210.118.204")
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 175.210.118.204, 10.244.2.1")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "175.210.118.204" {
		t.Fatalf("IP = %q, want 175.210.118.204 (envoy header beats XFF)", got.IP)
	}
}

// Empty or unparseable X-Envoy-External-Address must fall through to the
// XFF rightmost-untrusted walk so a misconfigured envoy doesn't blank out
// IP recording.
func TestExtract_Trust_XEnvoyExternalAddress_Garbage_FallsBackToXFF(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.2.54:443"
	r.Header.Set("X-Envoy-External-Address", "not-an-ip")
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 175.210.118.204, 10.244.2.1")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "175.210.118.204" {
		t.Fatalf("IP = %q, want 175.210.118.204 (XFF fallback)", got.IP)
	}
}

// Production XFF shape under our osaka topology:
//
//	user appended:           1.2.3.4         (spoofable, leftmost)
//	OCI Flexible LB appended: 175.210.118.204 (real client IP)
//	envoy appended:           10.244.2.1     (SNAT'd k8s node, in trusted CIDR)
//
// The rightmost-untrusted walk skips 10.244.2.1 (trusted) and returns
// 175.210.118.204, ignoring the spoofed leftmost entry. This locks the
// security contract for the deployment.
func TestExtract_Trust_XFFRightmostWalk_SkipsTrustedSuffix(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.2.54:443"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 175.210.118.204, 10.244.2.1")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "175.210.118.204" {
		t.Fatalf("IP = %q, want 175.210.118.204", got.IP)
	}
}

// Spoof regression test: a malicious leftmost in XFF must never become the
// recorded IP when the envoy header is absent and a trusted suffix exists.
func TestExtract_Trust_XFFSpoofedLeftmost_NotUsed(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.2.54:443"
	// Attacker sends a single-entry XFF; OCI LB appends the real IP; envoy
	// appends the SNAT'd node. The leftmost (attacker) must not win.
	r.Header.Set("X-Forwarded-For", "203.0.113.99, 175.210.118.204, 10.244.2.1")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP == "203.0.113.99" {
		t.Fatalf("IP = %q, leftmost spoof must never be returned", got.IP)
	}
	if got.IP != "175.210.118.204" {
		t.Fatalf("IP = %q, want 175.210.118.204", got.IP)
	}
}

// All XFF entries inside the trusted CIDR (degenerate config or internal
// loop) must fall back to the bare RemoteAddr instead of returning "".
func TestExtract_Trust_XFFAllTrusted_FallsBackToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.244.2.54:443"
	r.Header.Set("X-Forwarded-For", "10.244.0.5, 10.244.2.1")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "10.244.2.54" {
		t.Fatalf("IP = %q, want 10.244.2.54 (no untrusted entry → bare RemoteAddr)", got.IP)
	}
}

// When the immediate hop is outside the trusted CIDR, even a present
// X-Envoy-External-Address must be ignored — an attacker reaching the app
// directly must not be able to set the audit IP.
func TestExtract_UntrustedHop_IgnoresXEnvoyExternalAddress(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "198.51.100.7:51234"
	r.Header.Set("X-Envoy-External-Address", "1.2.3.4")
	got := Extract(r, mustParseTrusted(t, "10.244.0.0/16"))
	if got.IP != "198.51.100.7" {
		t.Fatalf("IP = %q, want 198.51.100.7 (untrusted hop must not honor envoy header)", got.IP)
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
