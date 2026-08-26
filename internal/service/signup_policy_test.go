package service

import "testing"

// signup-domain-001: an empty policy is the default and admits everyone.
// authgate is a generic gate; restricting signup has to be something the
// operator opts into, not something a fresh deployment inherits.
func TestSignupDomainPolicy_EmptyAdmitsEveryone(t *testing.T) {
	var p signupDomainPolicy
	for _, email := range []string{"a@example.com", "b@anything.test", ""} {
		if ok, reason := p.allows(email, true); !ok {
			t.Errorf("%q was refused by an empty policy (%s)", email, reason)
		}
	}
	// Even an unverified address: without a domain gate there is nothing for
	// verification to protect.
	if ok, _ := p.allows("a@example.com", false); !ok {
		t.Error("empty policy refused an unverified address")
	}
}

// signup-domain-002: matching is exact and case-insensitive on the address.
func TestSignupDomainPolicy_MatchesExactDomain(t *testing.T) {
	p := signupDomainPolicy{domains: []string{"example.com", "corp.test"}}

	allowed := []string{
		"user@example.com",
		"USER@EXAMPLE.COM",
		"  user@Example.Com  ",
		"user@corp.test",
		`"odd@local"@example.com`, // local part may itself contain @
	}
	for _, email := range allowed {
		if ok, reason := p.allows(email, true); !ok {
			t.Errorf("%q should be allowed, refused with %s", email, reason)
		}
	}

	refused := []string{
		"user@other.com",
		"user@sub.example.com",  // no implicit subdomain match
		"user@notexample.com",   // no suffix match
		"user@example.com.evil", // no prefix match
		"example.com",           // not an address at all
		"user@",
		"",
	}
	for _, email := range refused {
		if ok, _ := p.allows(email, true); ok {
			t.Errorf("%q should be refused", email)
		}
	}
}

// signup-domain-003: with the gate on, an unverified address is refused.
//
// The domain is only meaningful if the IdP vouched for it. Google verifies its
// own accounts, but authgate brokers whichever issuer it is pointed at, and one
// that hands out unverified addresses would let anyone claim the admitted
// domain — the gate would be decorative.
func TestSignupDomainPolicy_RefusesUnverifiedAddress(t *testing.T) {
	p := signupDomainPolicy{domains: []string{"example.com"}}

	ok, reason := p.allows("user@example.com", false)
	if ok {
		t.Fatal("unverified address was admitted despite matching the domain")
	}
	if reason != "email_unverified" {
		t.Errorf("reason = %q, want email_unverified", reason)
	}
}

// signup-domain-004: refusals carry a reason for the audit trail.
func TestSignupDomainPolicy_ReasonsAreDistinct(t *testing.T) {
	p := signupDomainPolicy{domains: []string{"example.com"}}

	for _, tc := range []struct {
		email    string
		verified bool
		want     string
	}{
		{"user@other.com", true, "domain_not_allowed"},
		{"user@example.com", false, "email_unverified"},
		{"not-an-address", true, "email_malformed"},
		// Failing both tests reports the domain, because verifying the address
		// would not get this person in.
		{"user@other.com", false, "domain_not_allowed"},
	} {
		if _, reason := p.allows(tc.email, tc.verified); reason != tc.want {
			t.Errorf("allows(%q, %v) reason = %q, want %q", tc.email, tc.verified, reason, tc.want)
		}
	}
}

// signup-domain-005: the policy trusts config to have normalized its input, so
// this pins the contract rather than silently papering over an un-normalized
// entry. If this ever fails, config.normalizeSignupDomains stopped running.
func TestSignupDomainPolicy_RequiresNormalizedEntries(t *testing.T) {
	p := signupDomainPolicy{domains: []string{"Example.COM"}}
	if ok, _ := p.allows("user@example.com", true); ok {
		t.Error("policy matched an un-normalized entry; normalization must happen in config")
	}
}
