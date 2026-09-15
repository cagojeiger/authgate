package clientaccess

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func mustNew(t *testing.T, allow Rules, deny DenyRules) *Policy {
	t.Helper()
	p, err := New(allow, deny)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// client-access-001: a missing policy and the explicit public policy admit
// everyone, verified or not.
func TestEvaluate_PublicAdmitsEveryone(t *testing.T) {
	for name, p := range map[string]*Policy{"nil": nil, "public": Public()} {
		if p.Restricted() {
			t.Errorf("%s: Restricted() = true", name)
		}
		for _, s := range []Subject{{}, {Email: "a@b.test"}, {Email: "a@b.test", EmailVerified: true, HostedDomain: "x.test"}} {
			if d := p.Evaluate(s); !d.Allowed || d.Reason != "" {
				t.Errorf("%s: Evaluate(%+v) = %+v, want allowed", name, s, d)
			}
		}
	}
}

// client-access-002: the evaluation matrix.
func TestEvaluate_Matrix(t *testing.T) {
	p := mustNew(t, Rules{
		GoogleWorkspaceDomains: []string{"Corp.Example"},
		EmailDomains:           []string{"partner.test", "*.partner.test"},
		Emails:                 []string{"Someone@Gmail.com"},
	}, DenyRules{Emails: []string{"former@corp.example", "someone@gmail.com"}})
	if !p.Restricted() {
		t.Fatal("Restricted() = false")
	}

	tests := []struct {
		name    string
		subject Subject
		allowed bool
		reason  string
	}{
		{"hd exact", Subject{Email: "x@personal.test", EmailVerified: true, HostedDomain: "corp.example"}, true, ""},
		{"hd case-insensitive", Subject{Email: "x@personal.test", EmailVerified: true, HostedDomain: "CORP.example"}, true, ""},
		{"hd match without verified email", Subject{Email: "x@corp.example", HostedDomain: "corp.example"}, true, ""},
		{"hd is exact, not suffix", Subject{Email: "x@personal.test", EmailVerified: true, HostedDomain: "sub.corp.example"}, false, ReasonNotAllowed},
		{"hd NULL does not match", Subject{Email: "x@corp.example", EmailVerified: true}, false, ReasonNotAllowed},
		{"hd rule is not an email rule", Subject{Email: "x@corp.example", EmailVerified: true, HostedDomain: "other.example"}, false, ReasonNotAllowed},
		{"email domain exact", Subject{Email: "a@partner.test", EmailVerified: true}, true, ""},
		{"email domain case-insensitive", Subject{Email: "A@PARTNER.TEST", EmailVerified: true}, true, ""},
		{"email domain wildcard", Subject{Email: "a@eu.partner.test", EmailVerified: true}, true, ""},
		{"wildcard respects label boundary", Subject{Email: "a@notpartner.test", EmailVerified: true}, false, ReasonNotAllowed},
		{"no prefix match", Subject{Email: "a@partner.test.evil", EmailVerified: true}, false, ReasonNotAllowed},
		{"email domain unverified", Subject{Email: "a@partner.test"}, false, ReasonEmailUnverified},
		{"email near miss", Subject{Email: "SOMEONE2@gmail.com", EmailVerified: true}, false, ReasonNotAllowed},
		{"unverified and unmatched is not_allowed", Subject{Email: "a@other.test"}, false, ReasonNotAllowed},
		{"deny wins over hd", Subject{Email: "Former@Corp.Example", EmailVerified: true, HostedDomain: "corp.example"}, false, ReasonDenyListed},
		{"deny wins over emails", Subject{Email: "someone@gmail.com", EmailVerified: true}, false, ReasonDenyListed},
		{"deny applies unverified", Subject{Email: "former@corp.example", HostedDomain: "corp.example"}, false, ReasonDenyListed},
		{"kelvin sign does not fold", Subject{Email: "a@\u212Apartner.test", EmailVerified: true}, false, ReasonNotAllowed},
		{"trailing space is not a domain", Subject{Email: "a@partner.test ", EmailVerified: true}, false, ReasonNotAllowed},
		{"empty", Subject{}, false, ReasonNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := p.Evaluate(tt.subject)
			if d.Allowed != tt.allowed || d.Reason != tt.reason {
				t.Fatalf("Evaluate(%+v) = %+v, want allowed=%v reason=%q", tt.subject, d, tt.allowed, tt.reason)
			}
		})
	}
}

// client-access-003: emails match exactly, ignoring ASCII case, and only when
// verified.
func TestEvaluate_Emails(t *testing.T) {
	p := mustNew(t, Rules{Emails: []string{"Someone@Gmail.com", "kim@gmail.com"}}, DenyRules{})
	for _, tt := range []struct {
		subject Subject
		want    Decision
	}{
		{Subject{Email: "someone@gmail.com", EmailVerified: true}, Decision{Allowed: true}},
		{Subject{Email: "SOMEONE@GMAIL.COM", EmailVerified: true}, Decision{Allowed: true}},
		{Subject{Email: "someone@gmail.com"}, Decision{Reason: ReasonEmailUnverified}},
		{Subject{Email: "someone2@gmail.com", EmailVerified: true}, Decision{Reason: ReasonNotAllowed}},
		{Subject{Email: "other@gmail.com", EmailVerified: true}, Decision{Reason: ReasonNotAllowed}},
		// Unicode case folding would turn the Kelvin sign into "k".
		{Subject{Email: "\u212Aim@gmail.com", EmailVerified: true}, Decision{Reason: ReasonNotAllowed}},
		// The address's domain alone does not match an emails entry.
		{Subject{Email: "x@gmail.com", EmailVerified: true, HostedDomain: "gmail.com"}, Decision{Reason: ReasonNotAllowed}},
	} {
		if got := p.Evaluate(tt.subject); got != tt.want {
			t.Errorf("Evaluate(%+v) = %+v, want %+v", tt.subject, got, tt.want)
		}
	}
}

// client-access-004: the wildcard does not include the domain itself.
func TestEvaluate_WildcardExcludesApex(t *testing.T) {
	p := mustNew(t, Rules{EmailDomains: []string{"*.example.com"}}, DenyRules{})
	if d := p.Evaluate(Subject{Email: "a@example.com", EmailVerified: true}); d.Allowed {
		t.Fatal("*.example.com admitted example.com")
	}
	if d := p.Evaluate(Subject{Email: "a@a.b.example.com", EmailVerified: true}); !d.Allowed {
		t.Fatal("*.example.com refused a.b.example.com")
	}
}

// client-access-010: invalid entries are refused so a typo fails startup.
func TestNew_Validation(t *testing.T) {
	tests := []struct {
		name  string
		allow Rules
		deny  DenyRules
		want  string
	}{
		{"empty allow", Rules{}, DenyRules{Emails: []string{"a@b.test"}}, "at least one"},
		{"empty entries only", Rules{EmailDomains: nil, Emails: []string{}}, DenyRules{}, "at least one"},
		{"bad domain", Rules{EmailDomains: []string{"exa mple.com"}}, DenyRules{}, "exa mple.com"},
		{"url as domain", Rules{EmailDomains: []string{"https://example.com"}}, DenyRules{}, "https://example.com"},
		{"unicode domain", Rules{EmailDomains: []string{"éxample.com"}}, DenyRules{}, "not a valid domain"},
		{"trailing dot", Rules{EmailDomains: []string{"example.com."}}, DenyRules{}, "not a valid domain"},
		{"bare tld wildcard", Rules{EmailDomains: []string{"*.com"}}, DenyRules{}, "no dot"},
		{"bare tld", Rules{EmailDomains: []string{"com"}}, DenyRules{}, "no dot"},
		{"inner wildcard", Rules{EmailDomains: []string{"a.*.example.com"}}, DenyRules{}, "'*'"},
		{"leading dot", Rules{EmailDomains: []string{".example.com"}}, DenyRules{}, "must not start with a dot"},
		{"empty domain entry", Rules{EmailDomains: []string{" "}}, DenyRules{}, "empty"},
		{"wildcard hd", Rules{GoogleWorkspaceDomains: []string{"*.corp.example"}}, DenyRules{}, "wildcards are not allowed"},
		{"bad hd", Rules{GoogleWorkspaceDomains: []string{"corp_example.com"}}, DenyRules{}, "google_workspace_domains"},
		{"email without at", Rules{Emails: []string{"someone.example.com"}}, DenyRules{}, "single address"},
		{"email with two ats", Rules{Emails: []string{"a@b@example.com"}}, DenyRules{}, "single address"},
		{"email empty local", Rules{Emails: []string{"@example.com"}}, DenyRules{}, "single address"},
		{"email space in local", Rules{Emails: []string{"a b@example.com"}}, DenyRules{}, "single address"},
		{"email bad domain", Rules{Emails: []string{"a@example..com"}}, DenyRules{}, "valid domain"},
		{"email tld only", Rules{Emails: []string{"a@localhost"}}, DenyRules{}, "valid domain"},
		{"deny bad email", Rules{Emails: []string{"a@example.com"}}, DenyRules{Emails: []string{"nope"}}, "deny.emails"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.allow, tt.deny)
			if err == nil {
				t.Fatal("New accepted an invalid policy")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

// client-access-011: entries are normalized (case, "@" prefix, whitespace) and
// duplicates collapse.
func TestNew_Normalizes(t *testing.T) {
	p := mustNew(t, Rules{
		GoogleWorkspaceDomains: []string{"CORP.example", "corp.example"},
		EmailDomains:           []string{" Example.COM ", "@example.com", "*.Example.com", "*.example.com"},
		Emails:                 []string{" Someone@Example.COM "},
	}, DenyRules{Emails: []string{"Former@Example.com", "former@example.com"}})
	if len(p.hostedDomains) != 1 || len(p.emailDomains) != 2 || len(p.emails) != 1 || len(p.denyEmails) != 1 {
		t.Fatalf("not deduplicated: hd=%v domains=%v emails=%v deny=%v", p.hostedDomains, p.emailDomains, p.emails, p.denyEmails)
	}
	if p.emailDomains[0] != "example.com" || p.emailDomains[1] != ".example.com" {
		t.Fatalf("emailDomains = %v", p.emailDomains)
	}
	if _, ok := p.emails["someone@example.com"]; !ok {
		t.Fatalf("emails = %v", p.emails)
	}
}

func decodeAccess(t *testing.T, doc string, strict bool) (*Policy, error) {
	t.Helper()
	var out struct {
		Access *Policy `yaml:"access"`
	}
	dec := yaml.NewDecoder(strings.NewReader(doc))
	dec.KnownFields(strict)
	err := dec.Decode(&out)
	return out.Access, err
}

// client-access-020: both YAML forms decode.
func TestUnmarshalYAML_Forms(t *testing.T) {
	p, err := decodeAccess(t, "access: public\n", true)
	if err != nil || p == nil || p.Restricted() {
		t.Fatalf("access: public = %+v, %v; want explicit public", p, err)
	}

	p, err = decodeAccess(t, `
access:
  allow:
    google_workspace_domains: [corp.example]
    email_domains: [partner.test, "*.partner.test"]
    emails: [someone@gmail.com]
  deny:
    emails: [former@corp.example]
`, true)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !p.Restricted() {
		t.Fatal("decoded policy is not restricted")
	}
	if d := p.Evaluate(Subject{Email: "x@eu.partner.test", EmailVerified: true}); !d.Allowed {
		t.Fatalf("wildcard from YAML not applied: %+v", d)
	}
	if d := p.Evaluate(Subject{Email: "former@corp.example", HostedDomain: "corp.example"}); d.Reason != ReasonDenyListed {
		t.Fatalf("deny from YAML not applied: %+v", d)
	}
}

// client-access-021: malformed access blocks are refused, and unknown keys are
// refused even by a decoder that does not enable KnownFields itself.
func TestUnmarshalYAML_Rejects(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"other scalar", "access: private\n", "public"},
		{"quoted public is a string", "access: \"public\"\n", ""},
		{"bool", "access: true\n", "public"},
		{"sequence", "access: [public]\n", "public"},
		{"no allow", "access:\n  deny:\n    emails: [a@b.test]\n", "allow is required"},
		{"null allow", "access:\n  allow:\n", "allow is required"},
		{"empty allow", "access:\n  allow: {}\n", "at least one"},
		{"unknown key in access", "access:\n  allow:\n    emails: [a@b.test]\n  denny:\n    emails: [c@d.test]\n", "denny"},
		{"unknown key in allow", "access:\n  allow:\n    email_domain: [b.test]\n    emails: [a@b.test]\n", "email_domain"},
		{"domains under deny", "access:\n  allow:\n    emails: [a@b.test]\n  deny:\n    email_domains: [b.test]\n", "email_domains"},
		{"bad domain", "access:\n  allow:\n    email_domains: [\"*.com\"]\n", "no dot"},
		{"bad email", "access:\n  allow:\n    emails: [nobody]\n", "single address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, strict := range []bool{true, false} {
				_, err := decodeAccess(t, tt.doc, strict)
				if tt.want == "" {
					// "public" quoted is still the string public.
					if err != nil {
						t.Fatalf("strict=%v: %v", strict, err)
					}
					continue
				}
				if err == nil {
					t.Fatalf("strict=%v: accepted %q", strict, tt.doc)
				}
				if !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("strict=%v: error %q does not mention %q", strict, err, tt.want)
				}
			}
		})
	}
}

func TestEmailDomain(t *testing.T) {
	for in, want := range map[string]string{
		"a@Example.com":            "example.com",
		`"a@b"@example.com`:        "example.com",
		"example.com":              "",
		"a@":                       "",
		"a@example.com.":           "",
		"a@\u212Aexample.com":      "",
		"a@exa mple.com":           "",
		"":                         "",
		"a@sub.Example.COM":        "sub.example.com",
		"someone@xn--bcher-kva.ch": "xn--bcher-kva.ch",
	} {
		if got := EmailDomain(in); got != want {
			t.Errorf("EmailDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
