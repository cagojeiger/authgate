# Contributing to authgate

## Getting started

```bash
git clone https://github.com/cagojeiger/authgate.git
cd authgate

# Run unit tests (no Docker required)
go test ./...

# Run integration tests (requires Docker)
go test -tags=integration ./...

# Run the full stack locally
docker compose up --build
```

## Before submitting a PR

1. **Tests** — add or update tests for any changed behavior
2. **Doc sync** — follow the rules in [CLAUDE.md](CLAUDE.md): each code change type maps to a doc that must be updated in the same commit
3. **No secrets** — never commit `.env` files, keys, or credentials

## Reporting bugs

Use [GitHub Issues](https://github.com/cagojeiger/authgate/issues).

**Security vulnerabilities** — do NOT file a public issue.
See [SECURITY.md](SECURITY.md) for the private reporting channel.

## Code style

- Standard Go formatting (`gofmt`)
- `go vet ./...` must pass
- Conventional commit messages: `feat:`, `fix:`, `chore:`, `docs:`, `test:`

## Integration tests

Integration tests use [testcontainers-go](https://testcontainers.com/guides/getting-started-with-testcontainers-for-go/) and require Docker:

```bash
go test -tags=integration ./internal/integration/...
go test -tags=integration ./internal/service/...
go test -tags=integration ./internal/storage/...
```
