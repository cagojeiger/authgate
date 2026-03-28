# authgate

Central authentication service for first-party applications with Google OIDC and mock provider support.

## Quick Start

Run everything with Docker Compose:

```bash
docker-compose up --build
```

Then open http://localhost:8081 in your browser.

## What You'll See

1. **Service A homepage** - A demo service that uses authgate
2. **Click "Sign In"** - Redirects to authgate
3. **Mock Login** - Choose Alice or Bob (no real credentials needed)
4. **Protected Content** - Shows your identity from authgate and local service state

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Service A  │────▶│  authgate   │────▶│  mock-idp   │
│  (localhost:8081) │  (localhost:8080) │  (localhost:8082) │
└─────────────┘     └──────┬──────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  PostgreSQL │
                    │  (localhost:5432) │
                    └─────────────┘
```

## Services

- **authgate** (port 8080) - Central OAuth2/OIDC provider
- **mock-idp** (port 8082) - Development identity provider
- **service-a** (port 8081) - Demo relying party
- **postgres** (port 5432) - Database

## Endpoints

### authgate
- `/.well-known/openid-configuration` - OIDC discovery
- `/.well-known/jwks.json` - Public keys
- `/oauth/authorize` - Authorization endpoint
- `/oauth/token` - Token endpoint
- `/oauth/logout` - Logout
- `/health` - Health check

## Development

### Project Structure
```
.
├── authgate/           # Central auth service
│   ├── cmd/authgate/   # Main entry
│   ├── internal/       # Internal packages
│   └── migrations/     # Database migrations
├── mock-idp/           # Mock OAuth provider
├── service-a/          # Demo service
├── docs/spec/          # OpenAPI specs
└── docker-compose.yml  # Local development
```

### Testing with Real Google OAuth

1. Create OAuth credentials at https://console.cloud.google.com
2. Set redirect URI to `http://localhost:8080/oauth/callback`
3. Update environment variables:

```yaml
environment:
  UPSTREAM_PROVIDER: "google"
  GOOGLE_CLIENT_ID: "your-client-id"
  GOOGLE_SECRET: "your-secret"
```

## OpenAPI Spec

See `docs/spec/openapi-slim.yaml` for the complete API specification.

## License

MIT