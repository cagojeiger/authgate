package storage

import (
	"context"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/kangheeyong/authgate/internal/clientaccess"
	"github.com/kangheeyong/authgate/internal/clientinfo"
)

// AccessSubject is the view of an account a client access policy evaluates.
func AccessSubject(u *User) clientaccess.Subject {
	return clientaccess.Subject{
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		HostedDomain:  u.HostedDomain,
	}
}

// AccessDeniedAuditMetadata builds the auth.access_denied metadata. It carries
// the email's domain, never the address: the domain is what an operator needs
// to tell which rule to change, and the audit log keeps no plaintext PII.
func AccessDeniedAuditMetadata(clientID, clientName, channel, reason, email string, signup bool) map[string]any {
	md := map[string]any{
		"client_id":   clientID,
		"client_name": clientName,
		"channel":     channel,
		"reason":      reason,
		"signup":      signup,
	}
	if domain := clientaccess.EmailDomain(email); domain != "" {
		md["domain"] = domain
	}
	return md
}

// enforceStaticClientAccess evaluates a static client's access policy against
// the stored account on a token path (code exchange, device polling, refresh).
// A refusal writes one auth.access_denied row for channel and returns
// invalid_grant, which the token endpoint answers with HTTP 400. A nil or
// public policy allows everyone and writes nothing.
func (s *Storage) enforceStaticClientAccess(ctx context.Context, access *clientaccess.Policy, clientID, channel string, user *User) error {
	decision := access.Evaluate(AccessSubject(user))
	if decision.Allowed {
		return nil
	}
	info := clientinfo.FromContext(ctx)
	s.AuditLog(ctx, &user.ID, EventAuthAccessDenied, info.IP, info.UserAgent,
		AccessDeniedAuditMetadata(clientID, s.staticClientName(clientID), channel, decision.Reason, user.Email, false))
	return &oidc.Error{ErrorType: "invalid_grant", Description: "account is not allowed to use this client"}
}
