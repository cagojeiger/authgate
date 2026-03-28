# 006. Data model

## Central auth tables

### users

```text
id
primary_email
email_verified
name
avatar_url
status
created_at
updated_at
```

### user_identities

```text
id
user_id
provider
provider_user_id
provider_email
created_at
```

### sessions

```text
id
user_id
expires_at
revoked_at
created_at
last_seen_at
```

### refresh_tokens

```text
id
user_id
session_id
token_hash
expires_at
rotated_from_id
revoked_at
created_at
```

### oauth_clients

```text
id
client_id
client_secret_hash
client_type
redirect_uris
post_logout_redirect_uris
audience
created_at
updated_at
```

### terms_documents

```text
id
scope
version
content_hash
published_at
```

### terms_acceptances

```text
id
user_id
scope
version
accepted_at
ip
user_agent
```

## Service-local tables (not in authgate)

### service_memberships

```text
id
issuer
subject
status
role
created_at
updated_at
```

### service_terms_acceptances

```text
id
issuer
subject
terms_version
accepted_at
```

## Boundary reminder

Do not let product services read authgate tables directly.

Integration happens through:

- OIDC/OAuth endpoints
- JWT validation via JWKS
- optional userinfo/introspection-like endpoints later if needed
