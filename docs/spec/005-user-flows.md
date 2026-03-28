# 005. User flows

## Signup flow

```text
User -> Product Service
     -> authgate login
     -> platform terms acceptance
     -> Google login
     -> authgate creates/links user
     -> authgate creates central session
     -> back to Product Service
     -> service upserts local member
     -> service checks service terms
     -> app access granted
```

## Web login flow

```text
User -> Service
     -> redirect to authgate /oauth/authorize
     -> Google / existing authgate session
     -> callback
     -> service exchanges code
     -> service validates token
     -> service creates local session
     -> app access granted
```

## Logout flow

```text
User -> Service logout
     -> clear local service session
     -> redirect to authgate /oauth/logout
     -> authgate clears central session
     -> redirect back to service
```

## CLI device flow

```text
CLI -> authgate /oauth/device/authorize
    <- device_code, user_code, verification_uri

User -> browser verification page
     -> authgate login if needed
     -> device approval

CLI -> poll token endpoint
    <- access token + refresh token
```

## CLI service usage

```text
CLI -> Service API with bearer token
    -> service validates JWT
    -> service checks local member / terms / authorization
    -> returns 200 / 403 / 428
```
