# authgate

Minimal B2C OAuth2/OIDC authentication gateway built with [zitadel/oidc v3](https://github.com/zitadel/oidc).

authgate embeds the OAuth/OIDC provider in-process, delegates user authentication to an upstream OIDC IdP, and owns:

- browser login and automatic signup
- device authorization approval (RFC 8628)
- MCP login routing
- token rotation and revocation
- account deletion and cleanup

Authgate is a pure authentication service. Business logic such as terms of service, privacy consent, and role management is the responsibility of each consuming application.

## Architecture

```text
             upstream OIDC IdP
                    │
                    │ code exchange / userinfo
                    v
┌─────────────────────────────────────────────┐
│                  authgate                   │
│                                             │
│  handler  ->  service  ->  storage -> sqlc  │
│    │             │            │         │    │
│    │             │            │         └─ PostgreSQL │
│    │             └─ upstream                 │
│    └─ pages                                  │
│                                             │
│  zitadel/oidc provider is embedded here     │
└─────────────────────────────────────────────┘
```

## Login Channels

| Channel | Endpoints | Purpose |
|---------|-----------|---------|
| Browser | `/login`, `/login/callback` | Web app login and signup |
| Device | `/device`, `/device/approve`, `/device/auth/callback` | CLI device flow approval |
| MCP | `/mcp/login`, `/mcp/callback` | MCP OAuth login |

## Endpoints

| Path | Description |
|------|-------------|
| `/.well-known/openid-configuration` | OIDC discovery |
| `/keys` | JWKS |
| `/authorize` | Authorization endpoint |
| `/oauth/token` | Token endpoint |
| `/oauth/revoke` | Token revocation (RFC 7009) |
| `/oauth/device/authorize` | Device authorization (RFC 8628) |
| `/end_session` | RP-Initiated Logout |
| `/userinfo` | UserInfo endpoint |
| `/account` | Account deletion (DELETE) |
| `/health` | Liveness check |
| `/ready` | Readiness check (DB ping) |

## Project Structure

```text
cmd/authgate/         main entrypoint
internal/
  config/             environment loading and validation
  db/
    queries/          handwritten SQL source (*.sql)
    storeq/           sqlc generated query layer (runtime DB contract)
  storage/            zitadel storage implementation + sqlc adapter orchestration
  service/            login, device, account, cleanup orchestration + access rules
  handler/            HTTP binding layer
  upstream/           upstream OIDC provider integration (rp-based)
  pages/              embedded HTML templates (device, error, result)
  clock/              time abstraction
  idgen/              UUID and opaque token generation
  integration/        httptest integration server helpers
  testutil/           testcontainers PostgreSQL helper
examples/
  webapp/             sample web app (BFF pattern, PKCE, JWT verification)
  cli/                device flow CLI test tool
migrations/           schema SQL (apply in order)
docs/
  adr/                architecture decisions
  architecture/       component boundaries
  spec/               product and system specs
  tests/              test design documents
```

## Quick Start (Docker Compose)

```bash
# Start infrastructure (DB + mock OIDC IdP)
make infra

# Start authgate (terminal 1)
make dev-authgate

# Start sample webapp (terminal 2)
make dev-sample-app

# Open http://localhost:9090 in browser
# Device flow: cd examples/cli && go run .
```

## Running (manual)

Prerequisites:

- PostgreSQL
- an upstream OIDC provider (or mock-idp via Docker)
- schema applied: `001_init.sql`, `002_mcp_resource_binding.sql`

```bash
# Apply migrations in order
psql -f migrations/001_init.sql
psql -f migrations/002_mcp_resource_binding.sql


# Start server
export DATABASE_URL='postgres://...'
export SESSION_SECRET='replace-with-32+-chars'
export PUBLIC_URL='http://localhost:8080'
export OIDC_ISSUER_URL='http://localhost:8082'
export OIDC_CLIENT_ID='authgate'
export OIDC_CLIENT_SECRET='replace-me'
export DEV_MODE=true

go run ./cmd/authgate
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | required | PostgreSQL connection string |
| `SESSION_SECRET` | required | provider crypto key source (>=32 chars in prod) |
| `PUBLIC_URL` | required | external authgate URL |
| `OIDC_ISSUER_URL` | `http://localhost:8082` | upstream OIDC issuer |
| `OIDC_INTERNAL_URL` | empty | internal URL for server-to-server OIDC calls (Docker/K8s) |
| `OIDC_CLIENT_ID` | `authgate` | upstream OIDC client ID |
| `OIDC_CLIENT_SECRET` | empty | upstream OIDC client secret |
| `PORT` | `8080` | listen port |
| `DEV_MODE` | `false` | allows insecure local development mode |
| `SESSION_TTL` | `86400` | session TTL in seconds |
| `ACCESS_TOKEN_TTL` | `900` | access token TTL in seconds |
| `REFRESH_TOKEN_TTL` | `2592000` | refresh token TTL in seconds |

Production guards when `DEV_MODE=false`:

- `SESSION_SECRET` must be at least 32 characters
- `OIDC_ISSUER_URL` must start with `https://`
- `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` are required
- session cookies are issued with `Secure=true`

## Testing

```bash
# unit tests
go test ./internal/config ./internal/clock ./internal/idgen

# integration tests (requires Docker for testcontainers-go)
go test -tags integration ./internal/storage ./internal/service ./internal/integration
```

## Specs

- Service specs: [docs/spec/](docs/spec/README.md)
- Architecture docs: [docs/architecture/](docs/architecture/README.md)
- Test design docs: [docs/tests/](docs/tests/README.md)

## License

Apache 2.0 — see [LICENSE](LICENSE)
