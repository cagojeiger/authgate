# 001. Product scope

## Goal

`authgate` is a central authentication service for three first-party products. It provides a shared login experience, issues tokens, and gives each service a stable user identity without becoming a full IAM platform.

## MVP includes

- Google OIDC upstream login
- Hosted login and callback flow
- Central browser session management
- JWT access token issuance
- Opaque rotating refresh tokens
- OIDC discovery and JWKS endpoints
- Client registration for first-party services
- Platform terms acceptance tracking
- Web and CLI/device login support

## MVP excludes

- Enterprise federation (SAML, LDAP, SCIM)
- Full admin console
- Central RBAC / permissions engine
- Service-specific terms ownership
- Service-specific role or membership ownership
- Complex multi-tenant / multi-realm support
- MFA for the first cut

## Ownership boundaries

### authgate owns

- users
- linked identities
- sessions
- refresh tokens
- auth audit events
- token signing keys
- platform-level consent

### product services own

- local member records
- service-specific onboarding
- service-specific terms acceptance
- authorization rules
- product data and lifecycle state

## Durable cross-service user key

All services identify users by:

```text
{iss, sub}
```

Email is profile data, not identity primary key.

## Open questions / deferred decisions

- Exact JWT signing algorithm: RS256 vs EdDSA
- Whether `userinfo` is needed in MVP or can stay optional
- Whether first release uses only server-rendered login UI or also a lightweight SDK-hosted helper
- Whether platform terms are required before Google redirect or immediately after first successful callback
- Whether refresh tokens are cookie-bound for web clients, stored by services, or both depending on client type
