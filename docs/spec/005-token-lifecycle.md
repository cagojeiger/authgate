# Spec 005: 토큰 Lifecycle

## 개요

authgate가 발급한 토큰의 갱신, 검증, 폐기 흐름.
로그인 방식(브라우저/CLI/MCP)에 관계없이 동일하게 적용된다.

## 토큰 종류

| 토큰 | 형식 | 수명 | 용도 |
|------|------|------|------|
| access_token | JWT (RS256) | 15분 (기본) | API 호출 |
| id_token | JWT (RS256) | 1시간 | 사용자 식별 확인 |
| refresh_token | opaque (UUID) | 30일 (기본) | access_token 갱신 |

## 토큰 갱신 (Refresh)

```mermaid
sequenceDiagram
    participant App as 앱
    participant AG as authgate

    Note over App,AG: access_token 만료 (15분 후)
    App->>AG: POST /oauth/token
    Note right of App: grant_type=refresh_token<br/>refresh_token=old_token<br/>client_id=my-app

    AG->>AG: hashToken(old_token)
    AG->>AG: DB 조회 (token_hash, revoked_at IS NULL, expires_at > NOW)

    alt 유효한 refresh_token
        AG->>AG: 구 토큰 revoke (revoked_at = NOW)
        AG->>AG: 신 refresh_token 생성 (family_id 상속)
        AG->>AG: 신 access_token JWT 서명
        AG-->>App: {access_token, refresh_token} (둘 다 새 것)
    else 만료/폐기된 토큰
        AG-->>App: 400 {error: "invalid_grant"}
    end
```

### Refresh Token Rotation

매 갱신마다 refresh_token도 새로 발급된다 (rotation).
구 토큰은 즉시 폐기. 같은 refresh_token을 두 번 사용할 수 없다.

```
family_id: 최초 로그인에서 생성된 UUID
  └── refresh_token_1 (발급 → 사용 → 폐기)
  └── refresh_token_2 (발급 → 사용 → 폐기)
  └── refresh_token_3 (현재 유효)
```

`family_id`는 하나의 로그인 세션에서 파생된 모든 refresh_token을 추적한다.

## 토큰 검증 (앱이 수행)

authgate는 토큰을 **발급**만 한다. **검증은 앱 책임**이다.

```mermaid
sequenceDiagram
    participant Client as 클라이언트
    participant App as 앱 서버
    participant AG as authgate

    Client->>App: API 요청 + Authorization: Bearer <access_token>

    Note over App: 첫 요청 시 JWKS 캐시
    App->>AG: GET /.well-known/jwks.json (캐시됨)
    AG-->>App: {keys: [{kty: RSA, kid: key-1, ...}]}

    App->>App: JWT 서명 검증 (RS256, JWKS 공개키)
    App->>App: iss 확인 (authgate URL과 일치?)
    App->>App: aud 확인 (내 client_id와 일치?)
    App->>App: exp 확인 (만료 안 됐나?)
    App->>App: sub 추출 → 유저 ID

    alt 검증 성공
        App->>App: sub로 자체 DB 조회 (권한, 플랜 등)
        App-->>Client: 200 응답
    else 검증 실패
        App-->>Client: 401 Unauthorized
    end
```

### 앱의 검증 체크리스트

| 항목 | 필수 | 설명 |
|------|------|------|
| 서명 검증 | **필수** | JWKS 공개키로 RS256 검증 |
| `iss` 확인 | **필수** | authgate의 issuer URL과 일치 |
| `aud` 확인 | **필수** | 자신의 client_id와 일치 |
| `exp` 확인 | **필수** | 현재 시각보다 미래 |
| JWKS 캐시 | **권장** | 매 요청마다 fetch하지 않음 |
| 키 회전 지원 | **권장** | JWKS 캐시 miss 시 재fetch |
| clock skew | **권장** | ±30초 허용 |

## 토큰 폐기 (Revoke)

```mermaid
sequenceDiagram
    participant App as 앱
    participant AG as authgate

    App->>AG: POST /oauth/revoke
    Note right of App: token=refresh_token

    AG->>AG: hashToken(token)
    AG->>AG: UPDATE refresh_tokens SET revoked_at = NOW
    AG-->>App: 200 OK
```

access_token(JWT)은 서버에서 폐기할 수 없다 — 만료(15분)를 기다린다.
즉시 차단이 필요하면 앱이 자체 blocklist를 운영해야 한다.

## 토큰 저장 보안

| 환경 | access_token | refresh_token |
|------|-------------|--------------|
| 웹 앱 (서버) | 세션/메모리 | DB 또는 세션 |
| 웹 앱 (SPA) | 메모리만 (localStorage 금지) | httpOnly 쿠키 또는 BFF 패턴 |
| CLI | secure storage | secure storage (`~/.config/`) |
| MCP 도구 | 도구 내부 메모리 | 도구 내부 storage |

## DB 저장

| 항목 | 저장 방식 |
|------|----------|
| refresh_token | SHA-256 해시로 저장. 평문 저장 안 함 |
| access_token | 저장 안 함 (JWT — stateless) |
| id_token | 저장 안 함 |
