# authgate Helm Chart

Helm chart for [authgate](https://github.com/cagojeiger/authgate), a minimal B2C OAuth2/OIDC authentication gateway built on `zitadel/oidc`.

## TL;DR

```bash
helm repo add authgate https://cagojeiger.github.io/authgate
helm repo update
helm install authgate authgate/authgate \
  --namespace authgate --create-namespace \
  --set authgate.publicUrl=https://auth.example.com \
  --set authgate.oidc.issuerUrl=https://idp.example.com \
  --set secrets.oidcClientSecret=YOUR_UPSTREAM_CLIENT_SECRET \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=auth.example.com \
  --set-string ingress.hosts[0].paths[0].path=/ \
  --set-string ingress.hosts[0].paths[0].pathType=Prefix
```

## What the chart deploys

- **authgate Deployment** (Go service on port 8080)
- **Service** (ClusterIP, optional Ingress)
- **ConfigMap** `clients.yaml` (OAuth client metadata)
- **Secret** holding the session secret, upstream OIDC client secret, and RSA signing key for token signing
- **PostgreSQL StatefulSet** (single replica, `postgres:17-alpine`, bundled by default) — can be disabled to use an external database
- **HPA** (optional)

Chart version and `appVersion` are kept in lock-step with the authgate Docker image tag via the `VERSION` file in the repo — the release workflow overrides both at package time.

## Prerequisites

- Kubernetes 1.25+
- Helm 3.12+
- A `StorageClass` in the cluster (for the bundled Postgres PVC) **or** set `postgresql.enabled=false` and provide an external database.
- Upstream OIDC IdP reachable from the cluster with a registered client for authgate.

## Required configuration

At minimum you must set:

| Key | Description |
|-----|-------------|
| `authgate.publicUrl` | External URL where authgate is reachable (must match the browser-facing URL exactly). |
| `authgate.oidc.issuerUrl` | Upstream OIDC IdP issuer URL. MUST start with `https://` when `devMode=false`. |
| `authgate.oidc.clientId` | Client ID registered with the upstream IdP. |
| `secrets.oidcClientSecret` | Upstream OIDC client secret. Required when `devMode=false`. |

## Secrets

By default the chart generates a random `session-secret` (48 chars) and an RSA signing key on first install. Both are preserved across `helm upgrade` via Helm's `lookup` function — they are **not** regenerated on upgrade.

If you delete the release or the Secret, new values are generated on reinstall and **all existing sessions, device codes, and refresh tokens become invalid** (they were signed/encrypted with the old key).

To manage secrets yourself, provide a pre-existing Kubernetes Secret with keys `session-secret`, `oidc-client-secret`, and `signing-key.pem`, and reference it via `secrets.existingSecret`.

## PostgreSQL

The chart bundles a single-replica Postgres StatefulSet using the official `postgres:17-alpine` image. The schema (`migrations/001_init.sql`) is mounted into `/docker-entrypoint-initdb.d/` and runs automatically on first boot of an empty data directory.

For production HA, disable the bundle and point at an external managed Postgres:

```yaml
postgresql:
  enabled: false

externalDatabase:
  existingSecret: authgate-db  # must contain a `database-url` key
```

## Clients

Define OAuth clients under `clients.clients`. The list is rendered verbatim into a `clients.yaml` ConfigMap mounted at `/etc/authgate/clients.yaml`.

```yaml
clients:
  clients:
    - client_id: sample-app
      client_type: public
      login_channel: browser
      name: Sample Web App
      redirect_uris:
        - https://sample.example.com/auth/callback
      allowed_scopes: [openid, profile, email, offline_access]
      allowed_grant_types: [authorization_code, refresh_token]
```

## Upgrading

```bash
helm upgrade authgate authgate/authgate -n authgate -f my-values.yaml
```

Chart upgrades are rolling — `checksum/*` annotations on the Deployment trigger a pod roll when ConfigMap/Secret contents change.

## Uninstalling

```bash
helm uninstall authgate -n authgate
```

**Note:** the Postgres PVC is NOT deleted by `helm uninstall`. To fully remove data:

```bash
kubectl -n authgate delete pvc -l app.kubernetes.io/component=postgres
```

## Values

See [`values.yaml`](./values.yaml) for the full list. Key sections:

- `replicaCount`, `image`, `resources`, `autoscaling`
- `authgate.*` — application config (TTLs, OIDC, HTTP tuning)
- `clients.clients` — OAuth client metadata
- `secrets.*` — session/OIDC/signing key
- `postgresql.*` — bundled Postgres (set `enabled: false` for external)
- `ingress.*` — Ingress (nginx, Traefik, etc.)
