# authgate specs

This directory contains the working specification for `authgate`, a central auth service for first-party applications.

## Document map

- `001-product-scope.md` — MVP scope, non-goals, ownership boundaries
- `002-architecture.md` — system shape and component responsibilities
- `003-identity-and-token-model.md` — identity model, sessions, tokens, claims
- `004-service-integration.md` — contract between authgate and downstream services
- `005-user-flows.md` — signup, web login, logout, and CLI/device flows
- `006-data-model.md` — initial database model and storage boundaries
- `openapi-slim.yaml` — OpenAPI 3.0 MVP specification (Oracle-reviewed, minimal surface)
- `openapi.yaml` — Complete OpenAPI spec (includes Phase 2 endpoints)

## Working principles

- `authgate` owns authentication, central identity, sessions, refresh tokens, and token issuance.
- Downstream services own local membership, service-specific terms, roles, and business authorization.
- Google is the upstream login provider, not the system of record for application identity.
- Spec docs should stay implementation-oriented and small enough to evolve quickly.
