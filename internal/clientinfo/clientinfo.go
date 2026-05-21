// Package clientinfo extracts trusted client IP and User-Agent from an HTTP
// request and threads the result through the request context. Proxy headers
// are honored only when the immediate hop is from a trusted proxy CIDR,
// preventing arbitrary clients from spoofing audit IP.
package clientinfo

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Info carries client identity derived from a request. IP is normalized to a
// PostgreSQL inet-compatible form (no port, no brackets); an empty string
// means the source value was missing or unparseable, and downstream callers
// should treat it the same as "no IP recorded" (i.e. NULL in audit_log).
// UserAgent is the raw header value with no truncation; storage callers are
// responsible for any size limits they enforce.
type Info struct {
	IP        string
	UserAgent string
}

// Extract returns Info derived from r. When r.RemoteAddr falls within a
// trusted CIDR, the search order is:
//  1. X-Envoy-External-Address — a single-IP header that an istio/envoy
//     ingressgateway populates with its trusted-client computation (see
//     numTrustedProxies/xff_num_trusted_hops). Envoy always overwrites any
//     incoming value, so this is spoof-resistant when the gateway is in
//     front.
//  2. X-Forwarded-For via rightmost-untrusted walk — scan entries from the
//     right, skip ones that fall inside a trusted CIDR, return the first
//     untrusted entry. Trusted entries represent proxy hops we control; the
//     first untrusted hop from the right is the original client (or the
//     closest untrusted proxy). Leftmost-XFF parsing is avoided because the
//     leftmost slot is freely settable by the client and not all upstream
//     proxies (e.g. OCI Flexible LB) sanitize incoming XFF.
//
// When r.RemoteAddr is outside the trusted set, both proxy headers are
// ignored and the bare RemoteAddr is returned. Pass nil or empty trusted to
// disable proxy trust entirely (safe default for self-deployed setups with
// no fronting proxy).
func Extract(r *http.Request, trusted []*net.IPNet) Info {
	if r == nil {
		return Info{}
	}
	hopIP := normalizeAddr(r.RemoteAddr)
	ip := hopIP
	if hopIP != "" && isTrustedHop(hopIP, trusted) {
		if envoy := normalizeAddr(r.Header.Get("X-Envoy-External-Address")); envoy != "" {
			ip = envoy
		} else if xff := rightmostUntrustedXFF(r.Header.Get("X-Forwarded-For"), trusted); xff != "" {
			ip = xff
		}
	}
	return Info{IP: ip, UserAgent: r.Header.Get("User-Agent")}
}

// ParseTrustedProxies parses a comma-separated list of CIDRs ("10.0.0.0/8,
// 192.168.0.0/16"). Empty input returns (nil, nil) meaning no proxy is
// trusted. Whitespace-only entries are skipped. Bare IPs without a /mask are
// rejected — operators must spell CIDRs explicitly to avoid ambiguity. If
// any single entry is invalid the entire list is rejected with an error,
// rather than silently using the valid prefix; this keeps the trust set a
// fail-closed configuration.
func ParseTrustedProxies(spec string) ([]*net.IPNet, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	var nets []*net.IPNet
	for _, raw := range strings.Split(spec, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			return nil, fmt.Errorf("clientinfo: %q must be a CIDR (e.g. 10.0.0.0/8)", entry)
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("clientinfo: invalid CIDR %q: %w", entry, err)
		}
		nets = append(nets, cidr)
	}
	return nets, nil
}

func isTrustedHop(ip string, trusted []*net.IPNet) bool {
	if len(trusted) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range trusted {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// normalizeAddr accepts forms like "1.2.3.4", "1.2.3.4:5678", "[::1]:1234",
// "::1", and bracketed bare IPv6 ("[::1]"), and returns a bare IP string. It
// returns "" when the input is missing or unparseable.
func normalizeAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if ip, err := netip.ParseAddr(addr); err == nil {
		return ip.String()
	}
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		if ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")); err == nil {
			return ip.String()
		}
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip, err := netip.ParseAddr(host); err == nil {
			return ip.String()
		}
	}
	return ""
}

// rightmostUntrustedXFF scans an X-Forwarded-For value right-to-left and
// returns the first entry not inside a trusted CIDR. Returns "" when the
// header is empty, every parseable entry is trusted, or no entry parses as
// an IP. Garbage entries are skipped silently so that a malformed proxy
// hop in the middle of a chain does not blank out a real client IP found
// further right.
func rightmostUntrustedXFF(value string, trusted []*net.IPNet) string {
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := normalizeAddr(parts[i])
		if ip == "" {
			continue
		}
		if !isTrustedHop(ip, trusted) {
			return ip
		}
	}
	return ""
}

type ctxKey struct{}

// WithContext attaches info to ctx. The returned context is suitable for
// passing to downstream handlers, services, and storage callers that need
// the client identity for audit-log writes.
func WithContext(ctx context.Context, info Info) context.Context {
	return context.WithValue(ctx, ctxKey{}, info)
}

// FromContext returns the Info attached to ctx via WithContext, or a zero
// Info if none was attached. It never panics and never returns nil.
func FromContext(ctx context.Context) Info {
	if ctx == nil {
		return Info{}
	}
	info, _ := ctx.Value(ctxKey{}).(Info)
	return info
}
