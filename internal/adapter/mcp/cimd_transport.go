package mcp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// newSSRFSafeHTTPClient builds the HTTP client used to fetch CIMD documents.
// Its DialContext resolves the host, then dials a verified public IP directly
// (defeating DNS rebinding), rejecting private/loopback/link-local/multicast
// and special-purpose ranges (isPrivateIP). Redirects are refused — a CIMD
// URL is the client_id, so following it elsewhere is not allowed — and every
// phase is tightly timed.
func newSSRFSafeHTTPClient() *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("cimd: invalid address: %s", addr)
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("cimd: DNS lookup failed: %w", err)
			}
			// Find first public IP and dial it directly (prevents DNS rebinding)
			for _, ip := range ips {
				if isPrivateIP(ip.IP) {
					continue
				}
				dialer := &net.Dialer{Timeout: 3 * time.Second}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			}
			return nil, fmt.Errorf("cimd: no public IP found for %s", host)
		},
		TLSHandshakeTimeout: 3 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("cimd: redirects not allowed")
		},
	}
}

// specialPurposeCIDRs are non-global special-use ranges that the net.IP
// helpers below do not cover. CGNAT 100.64.0.0/10 matters most: cloud pod
// networks (e.g. EKS VPC CNI) assign it to in-cluster workloads, so a CIMD
// client_id resolving there would let the fetcher reach internal services.
var specialPurposeCIDRs = mustParseCIDRs(
	"100.64.0.0/10",   // RFC 6598 CGNAT / shared address space
	"192.0.0.0/24",    // RFC 6890 IETF protocol assignments
	"192.0.2.0/24",    // RFC 5737 TEST-NET-1
	"198.51.100.0/24", // RFC 5737 TEST-NET-2
	"203.0.113.0/24",  // RFC 5737 TEST-NET-3
	"198.18.0.0/15",   // RFC 2544 benchmarking
	"240.0.0.0/4",     // reserved (incl. limited broadcast)
	"64:ff9b::/96",    // RFC 6052 NAT64 (embeds IPv4)
	"100::/64",        // RFC 6666 discard-only
	"2001:db8::/32",   // RFC 3849 documentation
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("cimd: invalid builtin CIDR " + c)
		}
		nets = append(nets, n)
	}
	return nets
}

// isPrivateIP checks if an IP is private/loopback/link-local/multicast or in
// a special-purpose range that must never be a CIMD fetch target.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Normalize IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) to IPv4.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	for _, n := range specialPurposeCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
