# 002. Architecture

## High-level shape

```text
Browser / CLI
    |
    v
 authgate
    |
    +-- Google OIDC
    |
    +-- Postgres
    |
    +-- JWKS / OIDC metadata
    |
    +-- issues tokens to
          Service A / Service B / Service C
```

## Core components

### 1. Login UI + callback handler

- Starts Google login
- Receives callback
- Creates or updates local user identity
- Creates central auth session

### 2. Session manager

- Browser session cookie lifecycle
- Session lookup and revocation
- Session expiry and logout behavior

### 3. Token service

- Signs JWT access tokens
- Issues rotating refresh tokens
- Publishes JWKS
- Publishes discovery metadata

### 4. Client registry

- Stores trusted first-party clients
- Validates redirect URIs
- Distinguishes web, CLI, and API clients

### 5. Consent manager

- Stores platform terms acceptance
- Tracks versioned consent records

## Design rules

- Keep authgate off the hot path for normal API validation.
- Services validate JWTs locally using JWKS.
- Avoid putting product authorization state into authgate tokens early.
- Keep browser login standard: authorization code + PKCE.

## Suggested implementation shape

```text
cmd/server
internal/http
internal/oidc
internal/user
internal/session
internal/token
internal/client
internal/consent
internal/storage
migrations
docs/spec
```
