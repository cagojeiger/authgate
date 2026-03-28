# 003. Identity and token model

## Identity model

### User

Represents the central account owned by authgate.

### Linked identity

Represents an upstream provider identity, initially only Google.

```text
user
  └── identity(provider=google, provider_user_id=sub)
```

## Session model

### Browser session

- Stored by authgate
- Backed by secure cookie + server record
- Used for central SSO continuity

### Service session

- Optional and local to each service
- Created after successful callback/token exchange
- Not shared by authgate directly

## Token model

### Access token

- Format: JWT
- Lifetime: 5–15 minutes
- Audience-specific
- Validated locally by services

### Refresh token

- Format: opaque random secret
- Stored hashed in DB
- Rotating on refresh
- Revoked on logout/session invalidation

## Required JWT claims

```json
{
  "iss": "https://auth.example.com",
  "sub": "usr_123",
  "aud": "service-a-api",
  "exp": 1710000000,
  "iat": 1710000000,
  "sid": "ses_123",
  "email": "user@example.com",
  "email_verified": true,
  "preferred_username": "kang",
  "name": "Kang"
}
```

## Rules

- `sub` must be stable for the lifetime of the user account.
- `aud` must be explicit for each downstream API.
- Service-specific roles should not be placed in the token by default.
- Platform consent state should not be used as a replacement for service-specific terms state.
