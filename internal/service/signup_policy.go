package service

import "strings"

// signupDomainPolicy decides which email domains may create an account.
//
// An empty policy admits everyone, which is the default: authgate is a generic
// gate and most deployments want whatever their IdP admits. An operator who
// sets SIGNUP_EMAIL_DOMAINS is narrowing that to a known set of domains.
//
// The policy gates signup only. Accounts that already exist keep working even
// if their domain is later removed from the list — locking out a live user is
// an account-lifecycle decision (user.Status), not a signup one, and doing it
// here would turn an operator's typo into a fleet-wide lockout.
// Entries must arrive already normalized — lowercase, bare domains — which is
// config's job (SIGNUP_EMAIL_DOMAINS is validated at startup so a typo fails
// there rather than silently locking out every new user). Matching here is
// exact, so "example.com" does not admit "evil.example.com"; a wildcard is a
// decision an operator should have to write out.
type signupDomainPolicy struct {
	// domains is normalized and non-empty only when enforcement is on.
	domains []string
}

func (p signupDomainPolicy) enabled() bool { return len(p.domains) > 0 }

// emailDomain returns the lowercased domain of an address, or "" if there is
// none. The local part may itself contain '@' when quoted, so the split is on
// the last one.
func emailDomain(email string) string {
	i := strings.LastIndex(email, "@")
	if i < 0 || i == len(email)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(email[i+1:]))
}

// allows reports whether an address may create an account, and why not when it
// may not. The reason is for the audit trail, not for the end user.
func (p signupDomainPolicy) allows(email string, emailVerified bool) (ok bool, reason string) {
	if !p.enabled() {
		return true, ""
	}
	// An unverified address cannot be trusted to prove its domain, so with the
	// allowlist on it is refused rather than matched. Google verifies its own
	// accounts, but authgate brokers whatever issuer it is pointed at, and an
	// issuer that hands out unverified addresses would make this gate a
	// formality — anyone could claim to be at the admitted domain.
	if !emailVerified {
		return false, "email_unverified"
	}
	domain := emailDomain(email)
	if domain == "" {
		return false, "email_malformed"
	}
	for _, d := range p.domains {
		if d == domain {
			return true, ""
		}
	}
	return false, "domain_not_allowed"
}
