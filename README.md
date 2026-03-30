# authgate

Minimal B2C OAuth2/OIDC authentication gateway built with [zitadel/oidc v3](https://github.com/zitadel/oidc).
Google OAuth login with terms/privacy consent, device flow, MCP support, and account lifecycle management.

## Quick Start

```bash
docker compose up --build -d

# Register demo OAuth clients
docker compose exec db psql -U authgate -c "
INSERT INTO oauth_clients (id, client_id, client_type, name, redirect_uris, allowed_scopes, allowed_grant_types, login_channel, created_at, updated_at) VALUES
  (uuid_generate_v4(), 'test-app', 'public', 'Demo App', '{http://localhost:9090/callback}', '{openid,profile,email,offline_access}', '{authorization_code,refresh_token}', 'browser', NOW(), NOW()),
  (uuid_generate_v4(), 'cli-client', 'public', 'Demo CLI', '{http://localhost:9090/callback}', '{openid,profile,email,offline_access}', '{authorization_code,urn:ietf:params:oauth:grant-type:device_code,refresh_token}', 'browser', NOW(), NOW()),
  (uuid_generate_v4(), 'mcp-client', 'public', 'Demo MCP', '{http://localhost:9091/callback}', '{openid,profile,email,offline_access}', '{authorization_code,refresh_token}', 'mcp', NOW(), NOW());
"
```

Then open http://localhost:9090 in your browser.

## Demo

### Browser Login (demo-app)
Open http://localhost:9090 and click **Login with authgate**.
Flow: authorize -> mock IdP -> callback -> terms consent -> token.

### CLI Device Flow (demo-cli)
```bash
go run demo/cli/main.go
```
Displays a user code, opens browser for approval, polls for token.

### MCP SSE (demo-mcp)
Get a token via demo-app, then:
```bash
curl -N -H "Authorization: Bearer <access_token>" http://localhost:9091/events
```

## Architecture

```
docker compose (5 services)
├── db          :5432  PostgreSQL 16
├── demo-idp    :8082  Mock Google OAuth
├── authgate    :8080  Authentication gateway
├── demo-app    :9090  Browser demo client
└── demo-mcp    :9091  MCP SSE demo server
```

## Login Channels

| Channel | Endpoint | Use case |
|---------|----------|----------|
| Browser | `/login`, `/login/callback`, `/login/terms` | Web app login + signup |
| Device  | `/device`, `/device/approve`, `/device/auth/callback` | CLI login |
| MCP     | `/mcp/login`, `/mcp/callback` | MCP tool server auth |

## Endpoints

| Path | Description |
|------|-------------|
| `/.well-known/openid-configuration` | OIDC discovery |
| `/authorize` | Authorization endpoint |
| `/oauth/token` | Token endpoint |
| `/oauth/revoke` | Token revocation (RFC 7009) |
| `/oauth/device/authorize` | Device authorization |
| `/userinfo` | UserInfo endpoint |
| `/keys` | JWKS |
| `/account` | DELETE for account deletion |
| `/health` | Health check |
| `/ready` | Readiness check (DB ping) |

## User Lifecycle

```
[unregistered]
    | Browser signup
    v
[active + initial_onboarding_incomplete]
    | terms/privacy/age consent
    v
[active + onboarding_complete] <-- normal state
    | terms version change
    v
[active + reconsent_required]
    | Browser re-consent
    v
[active + onboarding_complete]
    | DELETE /account
    v
[pending_deletion]
    |
    +-- Browser login --> recovery --> [active]
    |
    +-- 30 days --> cleanup --> [deleted]
                                  |
                                  | Same Google sub --> new signup
                                  v
                               [unregistered]
```

## Project Structure

```
cmd/authgate/         Main server
internal/
  config/             Environment variables (15 vars)
  guard/              DeriveLoginState + GuardLoginChannel (pure functions)
  storage/            op.Storage (25 methods), users, sessions, tokens, keys
  service/            Login, Device, Account, Cleanup services
  handler/            HTTP handlers (thin binding)
  upstream/           Google/Mock OAuth provider
  pages/              HTML templates (terms, device, result, error)
  clock/              Clock interface (real + fixed for tests)
  idgen/              UUID + opaque token generator
  integration/        httptest integration tests
  testutil/           testcontainers-go PostgreSQL helper
migrations/           PostgreSQL schema (8 tables)
demo/                 Standalone demo apps (no internal imports)
  shared/             Common mock IdP + OAuth helpers
  idp/                Mock Google OAuth server
  app/                Browser OAuth demo
  cli/                CLI device flow demo
  mcp/                MCP SSE server demo
docs/
  adr/                Architecture Decision Records
  spec/               Specifications (001-009)
  architecture/       Component boundaries
  tests/              Test specifications (001-004)
```

## Testing

```bash
# Unit tests (guard, config, clock, idgen)
go test ./internal/guard/ ./internal/config/ ./internal/clock/ ./internal/idgen/

# Integration tests (requires Docker for testcontainers-go)
go test -tags integration ./internal/storage/ ./internal/service/

# httptest integration tests (full OAuth flow with zitadel OP)
go test -tags integration ./internal/integration/
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | (required) | PostgreSQL connection string |
| `SESSION_SECRET` | (required) | Cookie encryption key (>=32 chars in prod) |
| `PUBLIC_URL` | (required) | External URL (e.g. https://auth.example.com) |
| `PORT` | 8080 | Listen port |
| `DEV_MODE` | false | Allow insecure cookies, mock provider |
| `UPSTREAM_PROVIDER` | mock | `google` or `mock` |
| `GOOGLE_CLIENT_ID` | | Google OAuth client ID |
| `GOOGLE_SECRET` | | Google OAuth client secret |
| `MOCK_IDP_URL` | http://localhost:8082 | Mock IdP internal URL |
| `MOCK_IDP_PUBLIC_URL` | http://localhost:8082 | Mock IdP browser-facing URL |
| `TERMS_VERSION` | 2026-03-28 | Current terms version |
| `PRIVACY_VERSION` | 2026-03-28 | Current privacy version |
| `SESSION_TTL` | 86400 | Session duration (seconds) |
| `ACCESS_TOKEN_TTL` | 900 | Access token duration (seconds) |
| `REFRESH_TOKEN_TTL` | 2592000 | Refresh token duration (seconds) |

## Production

Set `DEV_MODE=false` to enforce:
- `SESSION_SECRET` >= 32 characters
- `UPSTREAM_PROVIDER=google` (mock not allowed)
- `GOOGLE_CLIENT_ID` and `GOOGLE_SECRET` required
- Secure cookies (HTTPS only)

## License

MIT
