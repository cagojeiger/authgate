package mcp

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/kangheeyong/authgate/internal/domainname"
)

// AnyCIMDHost is the allowlist entry that admits a CIMD document from any
// host. It must be the only entry.
const AnyCIMDHost = "*"

// DefaultCIMDHosts are the MCP clients authgate is used from. A CIMD client
// is registered by nothing more than serving a JSON document, so without an
// allowlist anyone can publish one naming their own redirect_uris and, because
// the MCP channel approves without a consent screen, receive a signed-in
// user's authorization code for an MCP resource.
var DefaultCIMDHosts = []string{"claude.ai", "chatgpt.com"}

// CIMDHostPolicy decides which hosts may serve a CIMD client document. Its
// zero value admits no host.
type CIMDHostPolicy struct {
	any   bool
	hosts map[string]struct{}
}

// NewCIMDHostPolicy builds a policy from exact host names. A host matches only
// itself: "claude.ai" does not admit "evil.claude.ai". The single entry "*"
// admits every host.
func NewCIMDHostPolicy(hosts []string) (CIMDHostPolicy, error) {
	if len(hosts) == 0 {
		return CIMDHostPolicy{}, fmt.Errorf("cimd host allowlist is empty")
	}
	for _, h := range hosts {
		if h == AnyCIMDHost {
			if len(hosts) != 1 {
				return CIMDHostPolicy{}, fmt.Errorf("cimd host allowlist: %q must be the only entry", AnyCIMDHost)
			}
			return CIMDHostPolicy{any: true}, nil
		}
	}
	set := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		if !domainname.Valid(h) || h != strings.ToLower(h) {
			return CIMDHostPolicy{}, fmt.Errorf("cimd host allowlist: %q is not a lowercase host name", h)
		}
		set[h] = struct{}{}
	}
	return CIMDHostPolicy{hosts: set}, nil
}

// allowsClientID reports whether clientID is served from an allowed host.
// The port is not part of the match: a document on another port of an allowed
// host is still published by that host's owner.
func (p CIMDHostPolicy) allowsClientID(clientID string) bool {
	if p.any {
		return true
	}
	u, err := url.Parse(clientID)
	if err != nil {
		return false
	}
	_, ok := p.hosts[u.Hostname()]
	return ok
}

func cimdHost(clientID string) string {
	u, err := url.Parse(clientID)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
