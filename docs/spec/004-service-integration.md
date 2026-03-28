# 004. Service integration contract

## Authgate exposes

```text
GET  /.well-known/openid-configuration
GET  /.well-known/jwks.json
GET  /oauth/authorize
POST /oauth/token
POST /oauth/revoke
GET  /oauth/logout
GET  /oauth/userinfo   (optional)
POST /oauth/device/authorize
POST /oauth/device/token
```

## Each service must do

### Browser apps

- redirect to `/oauth/authorize`
- handle callback
- exchange code for token
- create local session if needed
- upsert local member using `{iss, sub}`
- enforce service-specific terms locally

### APIs

- validate JWT locally using JWKS
- verify `iss`, `aud`, `exp`
- map token into internal principal

## Standard response semantics

```text
401 Unauthorized
- missing token
- expired token
- invalid signature

403 Forbidden
- member not allowed
- member suspended
- insufficient service authorization

428 Precondition Required
- service terms acceptance required
```

## Internal principal example

```json
{
  "issuer": "https://auth.example.com",
  "subject": "usr_123",
  "email": "user@example.com",
  "displayName": "Kang",
  "sessionId": "ses_123"
}
```

## Important boundary

`authgate` proves identity.

Each service decides:

- whether the user has a member record
- whether the user accepted current service terms
- what the user may do inside the product
