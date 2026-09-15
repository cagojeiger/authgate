// Package clientaccess decides which authgate accounts may use a client.
//
// A client registered in clients.yaml may carry an access policy. Without one
// the client is public: every authgate account may sign in to it, which is how
// every client behaved before policies existed. With one, a login, a device
// approval or a refresh for that client succeeds only for accounts the policy
// admits.
//
// The package holds no I/O. Storage attaches a compiled *Policy to each static
// client; the service and storage layers evaluate it against the email,
// email_verified and Google hosted domain the IdP just asserted (upstream
// callbacks) or the account's stored ones (every path without an IdP round trip).
package clientaccess

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kangheeyong/authgate/internal/domainname"
)

// Reasons an account is refused. They go to the audit trail, never to the user.
const (
	// ReasonDenyListed: the account's email is on the deny list.
	ReasonDenyListed = "deny_listed"
	// ReasonNotAllowed: no allow rule matched.
	ReasonNotAllowed = "not_allowed"
	// ReasonEmailUnverified: an email rule would have matched, but the address
	// is unverified and so proves nothing.
	ReasonEmailUnverified = "email_unverified"
)

// Rules is the allow block of an access policy as written in clients.yaml.
type Rules struct {
	// GoogleWorkspaceDomains matches the Google hosted domain (the hd claim)
	// exactly. Only Google Workspace accounts carry one.
	GoogleWorkspaceDomains []string `yaml:"google_workspace_domains"`
	// EmailDomains matches the domain of a verified email: "example.com"
	// exactly, "*.example.com" any subdomain but not example.com itself.
	EmailDomains []string `yaml:"email_domains"`
	// Emails matches a verified email exactly, ignoring ASCII case.
	Emails []string `yaml:"emails"`
}

// DenyRules is the deny block of an access policy as written in clients.yaml.
type DenyRules struct {
	// Emails refuses these addresses whatever the allow rules say.
	Emails []string `yaml:"emails"`
}

// Policy is a validated, normalized access policy. The zero value is not
// useful; build one with New or Public, or decode one from YAML.
type Policy struct {
	public bool

	hostedDomains map[string]struct{}
	// emailDomains holds exact domains ("example.com") and wildcard suffixes
	// (".example.com"). The leading dot is the label boundary, so a wildcard
	// match is a suffix test that cannot be fooled by "notexample.com".
	emailDomains []string
	emails       map[string]struct{}
	denyEmails   map[string]struct{}
}

// Public returns the explicit public policy ("access: public"): every account
// is admitted. It differs from no policy only in that the operator said so.
func Public() *Policy { return &Policy{public: true} }

// New validates and normalizes an allow/deny policy. At least one allow entry
// is required: an allow block that lists nothing would refuse everyone, which
// is never what an operator who wrote it meant.
func New(allow Rules, deny DenyRules) (*Policy, error) {
	p := &Policy{
		hostedDomains: map[string]struct{}{},
		emails:        map[string]struct{}{},
		denyEmails:    map[string]struct{}{},
	}
	for _, entry := range allow.GoogleWorkspaceDomains {
		d, err := normalizeDomain(entry, false)
		if err != nil {
			return nil, fmt.Errorf("allow.google_workspace_domains: %w", err)
		}
		p.hostedDomains[d] = struct{}{}
	}
	seen := map[string]struct{}{}
	for _, entry := range allow.EmailDomains {
		d, err := normalizeDomain(entry, true)
		if err != nil {
			return nil, fmt.Errorf("allow.email_domains: %w", err)
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		p.emailDomains = append(p.emailDomains, d)
	}
	for _, entry := range allow.Emails {
		e, err := normalizeEmail(entry)
		if err != nil {
			return nil, fmt.Errorf("allow.emails: %w", err)
		}
		p.emails[e] = struct{}{}
	}
	for _, entry := range deny.Emails {
		e, err := normalizeEmail(entry)
		if err != nil {
			return nil, fmt.Errorf("deny.emails: %w", err)
		}
		p.denyEmails[e] = struct{}{}
	}
	if len(p.hostedDomains) == 0 && len(p.emailDomains) == 0 && len(p.emails) == 0 {
		return nil, errors.New("allow must list at least one of google_workspace_domains, email_domains or emails; write access: public to admit everyone")
	}
	return p, nil
}

// Restricted reports whether the policy can refuse anyone. A nil policy (no
// access key) and the explicit public policy are not restricted.
func (p *Policy) Restricted() bool { return p != nil && !p.public }

// Subject is what a policy is evaluated against: an upstream login's assertions
// or the account as authgate stores it. Names are deliberately absent; they
// prove nothing.
type Subject struct {
	Email         string
	EmailVerified bool
	// HostedDomain is the Google hosted domain of the upstream login or, when
	// stored, of the account's last one; empty when there is none or the
	// account has not signed in since authgate started recording it.
	HostedDomain string
}

// Decision is the outcome of an evaluation. Reason is set only when refused.
type Decision struct {
	Allowed bool
	Reason  string
}

// Evaluate decides whether s may use the client. The deny list is checked
// first and wins over every allow rule; it applies whether or not the address
// is verified, because refusing a claimed address can only refuse the
// claimant. Allow rules are OR-ed. Email rules match only a verified address.
func (p *Policy) Evaluate(s Subject) Decision {
	if !p.Restricted() {
		return Decision{Allowed: true}
	}
	email := asciiLower(s.Email)
	if _, denied := p.denyEmails[email]; denied {
		return Decision{Reason: ReasonDenyListed}
	}
	if hd := asciiLower(s.HostedDomain); hd != "" {
		if _, ok := p.hostedDomains[hd]; ok {
			return Decision{Allowed: true}
		}
	}
	if !p.matchesEmail(email) {
		return Decision{Reason: ReasonNotAllowed}
	}
	// Reported only when verifying the address would change the outcome;
	// otherwise it would send an operator chasing verification for nothing.
	if !s.EmailVerified {
		return Decision{Reason: ReasonEmailUnverified}
	}
	return Decision{Allowed: true}
}

func (p *Policy) matchesEmail(email string) bool {
	if _, ok := p.emails[email]; ok {
		return true
	}
	domain := EmailDomain(email)
	if domain == "" {
		return false
	}
	for _, d := range p.emailDomains {
		if d[0] == '.' {
			if strings.HasSuffix(domain, d) {
				return true
			}
			continue
		}
		if d == domain {
			return true
		}
	}
	return false
}

// EmailDomain returns the lowercased domain of an address, or "" if it has no
// valid one. The split is on the last '@'. The domain must be an ASCII DNS
// name: Unicode lowercasing would let a look-alike such as the Kelvin sign fold
// into an admitted ASCII domain.
func EmailDomain(email string) string {
	i := strings.LastIndex(email, "@")
	if i < 0 {
		return ""
	}
	domain := email[i+1:]
	if !domainname.Valid(domain) {
		return ""
	}
	return asciiLower(domain)
}

// normalizeDomain canonicalizes a domain entry to lowercase and rejects
// anything that could never match. With allowWildcard, "*.example.com" is
// accepted and stored as ".example.com". "@example.com" is accepted as
// "example.com".
func normalizeDomain(entry string, allowWildcard bool) (string, error) {
	d := asciiLower(strings.TrimSpace(entry))
	d = strings.TrimPrefix(d, "@")
	if d == "" {
		return "", errors.New("entry is empty")
	}
	wildcard := strings.HasPrefix(d, "*.")
	if wildcard && !allowWildcard {
		return "", fmt.Errorf("%q: wildcards are not allowed here; list each domain", entry)
	}
	base := strings.TrimPrefix(d, "*.")
	if strings.Contains(base, "*") {
		return "", fmt.Errorf("%q: '*' is only allowed as a leading \"*.\" label", entry)
	}
	if strings.HasPrefix(base, ".") {
		return "", fmt.Errorf("%q must not start with a dot; write example.com or *.example.com", entry)
	}
	if strings.ContainsAny(base, "@ \t") {
		return "", fmt.Errorf("%q must be a bare domain like example.com", entry)
	}
	if !domainname.Valid(base) {
		return "", fmt.Errorf("%q is not a valid domain; use letters, digits and hyphens, and the xn-- form for internationalized domains", entry)
	}
	// Also what stops "*.com": its base has no dot, so a wildcard always sits
	// under a two-label domain. This is not a public-suffix check.
	if !strings.Contains(base, ".") {
		return "", fmt.Errorf("%q has no dot; expected something like example.com", entry)
	}
	if wildcard {
		return "." + base, nil
	}
	return base, nil
}

// normalizeEmail lowercases an address entry and requires exactly one '@', a
// non-empty local part without whitespace, and a valid domain.
func normalizeEmail(entry string) (string, error) {
	e := asciiLower(strings.TrimSpace(entry))
	if strings.Count(e, "@") != 1 {
		return "", fmt.Errorf("%q must be a single address like someone@example.com", entry)
	}
	i := strings.LastIndex(e, "@")
	local, domain := e[:i], e[i+1:]
	if local == "" || strings.ContainsAny(local, " \t\r\n") {
		return "", fmt.Errorf("%q must be a single address like someone@example.com", entry)
	}
	if !domainname.Valid(domain) || !strings.Contains(domain, ".") {
		return "", fmt.Errorf("%q does not have a valid domain", entry)
	}
	return e, nil
}

// asciiLower folds only A-Z. Unicode case folding would let distinct addresses
// compare equal (the Kelvin sign lowercases to "k").
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}
