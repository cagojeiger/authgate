# Spec 004: MCP Authorization (OAuth 2.1 + Protected Resource)

## 개요

AI 도구(Claude Desktop, Cursor 등)가 원격 MCP 서버에 접근하기 위해 authgate에서 인증하고
`access_token + refresh_token`을 받는 플로우.

이 스펙의 핵심은 "MCP 로그인 화면"이 아니라, 아래 3개 컴포넌트가 어떤 계약으로 상호작용하는지다.

```text
+------------------+        +------------------+        +------------------+
|   MCP Client     |        |    MCP Server    |        |    authgate      |
| Claude/Cursor    |        | protected res.   |        | authorization sv |
+--------+---------+        +--------+---------+        +--------+---------+
         |                           |                           |
         | resource metadata 조회    |                           |
         |-------------------------->|                           |
         |<--------------------------|                           |
         |                           |                           |
         | auth server metadata 조회 |                           |
         |------------------------------------------------------>|
         |<------------------------------------------------------|
         |                           |                           |
         | authorize / token (CIMD)  |                           |
         |------------------------------------------------------>|
         |<------------------------------------------------------|
         |                           |                           |
         | access_token 사용         |                           |
         |-------------------------->|                           |
         |<--------------------------|                           |
```

**사용자는 브라우저 가입(Spec 001)이 완료된 상태여야 한다.**
MCP는 Browser/Device와 같은 "후속 로그인 채널"이며, 신규 가입 채널이 아니다.

## 본질

MCP는 브라우저 로그인과 같은 `authorization_code + PKCE`를 사용하지만,
역할 분리가 더 명확하다.

```text
Browser 로그인
  = 사용자가 직접 앱에 들어가기 위한 로그인

MCP Authorization
  = AI 도구가 특정 MCP 서버(resource)에 접근하기 위한 OAuth 2.1 계약
```

따라서 MCP에서는 다음 요소가 함께 성립해야 한다.

```text
1. authgate는 Authorization Server
2. MCP 서버는 Protected Resource
3. MCP 클라이언트는 resource 파라미터를 포함해 토큰을 요청
4. authgate는 MCP 전용 로그인 경로(/mcp/login, /mcp/callback)를 사용
5. MCP 서버는 받은 access_token이 "자기 resource 용도"인지 검증
```

## 전제

- authgate에서 `zitadel/oidc`는 **내장 라이브러리**다. 별도 서버가 아니다.
- MCP 클라이언트는 OAuth 2.1 `authorization_code + PKCE(S256)`를 지원해야 한다.
- MCP 클라이언트는 RFC 8414 metadata를 사용할 수 있어야 한다.
- MCP 클라이언트는 CIMD (Client ID Metadata Document)를 지원해야 한다. DCR(RFC 7591)은 지원하지 않는다.
- **성공적으로 MCP 토큰을 발급받으려면** `user.Status = 'active'` 여야 한다.
- 사용자는 브라우저 접근 가능해야 한다.
- 원격 MCP 서버는 HTTP 기반 protected resource여야 한다.
- 예제 서버는 `Streamable HTTP` 방식으로 구현되어 있다.

## 역할

### MCP Client

```text
책임
  - protected resource metadata 조회
  - authorization server metadata 조회
  - CIMD: HTTPS URL에 client metadata document 호스팅
  - PKCE 생성
  - /authorize, /oauth/token 호출
  - localhost redirect 수신
  - access_token으로 MCP 서버 호출
```

### MCP Server

```text
책임
  - /.well-known/oauth-protected-resource 제공
  - 401 + WWW-Authenticate 에 resource_metadata 힌트 제공
  - access_token 검증
  - 자기 resource에 맞는 토큰만 허용
```

### authgate

```text
책임
  - /.well-known/oauth-authorization-server 제공 (client_id_metadata_document_supported: true)
  - /authorize, /oauth/token, /oauth/revoke 제공
  - CIMD: URL 형식 client_id 감지 → metadata fetch → 검증
  - MCP 전용 로그인 경로(/mcp/login, /mcp/callback) 처리
  - user 상태 정책 적용
  - JWT access_token / opaque refresh_token 발급
```

## 관련 엔드포인트

### authgate

| Method | Path | 설명 |
|--------|------|------|
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 Authorization Server Metadata (CIMD 지원 광고 포함) |
| GET | `/.well-known/openid-configuration` | OIDC Discovery fallback |
| GET | `/authorize` | Authorization Code + PKCE 시작 (URL 형식 client_id → CIMD fetch) |
| GET | `/mcp/login` | MCP 전용 로그인 진입 |
| GET | `/mcp/callback` | MCP 전용 upstream callback |
| POST | `/oauth/token` | code + code_verifier → 토큰 발급 |
| POST | `/oauth/revoke` | refresh_token 폐기 |
| GET | `/keys` | JWT 검증용 JWKS |
| GET | `/userinfo` | Bearer 토큰 기반 userinfo |

### MCP Server

| Method | Path | 설명 |
|--------|------|------|
| GET | `/.well-known/oauth-protected-resource` | RFC 9728 Protected Resource Metadata |
| POST/GET | `/mcp` | 실제 MCP transport endpoint |
| GET | `/health` | 헬스체크 |

## 표준

- OAuth 2.1 draft (`authorization_code + PKCE`, public client 전제)
- RFC 7636 (PKCE, `S256` 필수)
- RFC 8414 (OAuth Authorization Server Metadata)
- RFC 8707 (Resource Indicators)
- RFC 9728 (OAuth Protected Resource Metadata)
- draft-ietf-oauth-client-id-metadata-document (CIMD)
- MCP Authorization spec (2025-11-25)

## Browser / Device와의 차이

| 항목 | Browser (Spec 002) | Device (Spec 003) | MCP (이 스펙) |
|------|-------------------|-------------------|---------------|
| 누가 토큰을 쓰는가 | 웹 앱/사용자 | CLI 도구 | AI 도구 |
| 사용자 상호작용 | 브라우저 직접 | 브라우저 승인 | 브라우저 로그인 + 도구 자동 호출 |
| grant | auth code + PKCE | device_code | auth code + PKCE |
| discovery 시작점 | auth server | auth server | protected resource → auth server |
| 추가 파라미터 | 없음 | 없음 | `resource` |
| client 유형 | public/confidential | 보통 public | 보통 public |
| 로그인 경로 | `/login` | `/device` | `/mcp/login` |
| callback 경로 | `/login/callback` | `/device/auth/callback` | `/mcp/callback` |

## 플로우

```mermaid
sequenceDiagram
    participant C as MCP Client
    participant R as MCP Server
    participant AG as authgate
    participant U as 사용자 브라우저
    participant G as Upstream IdP

    Note over C,G: 1. Protected Resource Discovery
    C->>R: GET /.well-known/oauth-protected-resource
    R-->>C: {resource, authorization_servers}

    Note over C,G: 2. Authorization Server Discovery
    C->>AG: GET /.well-known/oauth-authorization-server
    AG-->>C: {authorization_endpoint, token_endpoint, client_id_metadata_document_supported: true, ...}

    Note over C,G: 3. Authorization Request (CIMD)
    C->>U: 브라우저 열기
    Note right of C: client_id = https://app.example.com/oauth/client.json (CIMD URL)
    U->>AG: GET /authorize?...&client_id=https://app.example.com/oauth/client.json&redirect_uri=http://localhost:PORT/callback&code_challenge=...&code_challenge_method=S256&resource=https://mcp.example.com
    AG->>AG: client_id가 URL → CIMD fetch
    AG->>C: GET https://app.example.com/oauth/client.json
    C-->>AG: {client_id, client_name, redirect_uris, ...}
    AG->>AG: client_id 일치 + redirect_uri 검증 + PKCE 검증
    AG->>AG: auth_request 생성
    AG-->>U: 302 /mcp/login?authRequestID=...

    Note over C,G: 4. MCP 전용 로그인
    U->>AG: GET /mcp/login?authRequestID=...
    alt 유효한 브라우저 세션 + active
        AG->>AG: auth_request 완료
    else 세션 없음
        AG-->>U: 302 Upstream IdP
        U->>G: 로그인
        G-->>U: 302 /mcp/callback?code=...&state=authRequestID
        U->>AG: GET /mcp/callback?code=...&state=...
        AG->>AG: 기존 유저 조회 + 상태 검사
        AG->>AG: session 생성 + auth_request 완료
    else 비활성/삭제 유예
        AG-->>U: 403 account_inactive
    else 미가입
        AG-->>U: 403 account_not_found
    end

    Note over C,G: 5. Token Exchange
    U-->>C: localhost callback ?code=...&state=...
    C->>AG: POST /oauth/token
    Note right of C: grant_type=authorization_code<br/>client_id=...<br/>code=...<br/>code_verifier=...<br/>resource=https://mcp.example.com
    AG->>AG: auth_request / user 상태 재검사
    AG-->>C: {access_token, refresh_token, id_token}

    Note over C,G: 6. MCP Resource Access
    C->>R: Authorization: Bearer <access_token>
    R->>R: signature / iss / exp / aud(resource) 검증
    R-->>C: MCP 응답
```

## Discovery

MCP에서는 보통 Authorization Server discovery보다 **Protected Resource discovery**가 먼저 온다.

```text
MCP Client
  -> MCP Server의 resource metadata 조회
  -> authorization_servers 목록 획득
  -> 그 중 authgate metadata 조회
```

### Protected Resource Metadata

MCP 서버는 `/.well-known/oauth-protected-resource`에서 최소한 아래를 제공해야 한다.

```json
{
  "resource": "https://mcp.example.com",
  "authorization_servers": ["https://auth.example.com"]
}
```

### Authorization Server Metadata

authgate는 `/.well-known/oauth-authorization-server`에서 최소한 아래를 제공해야 한다.

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "revocation_endpoint": "https://auth.example.com/oauth/revoke",
  "client_id_metadata_document_supported": true
}
```

## Client ID Metadata Document (CIMD)

MCP 클라이언트는 어떤 MCP 서버에 연결될지 사전에 알 수 없기 때문에,
사전 등록 없이 클라이언트를 식별할 수 있는 방법이 필요하다.

authgate는 CIMD (`draft-ietf-oauth-client-id-metadata-document`)를 지원한다.
MCP 클라이언트는 HTTPS URL에 메타데이터 JSON을 호스팅하고, 그 URL을 `client_id`로 사용한다.

```text
MCP 클라이언트가 호스팅하는 메타데이터 예시:
GET https://app.example.com/oauth/client.json

{
  "client_id": "https://app.example.com/oauth/client.json",
  "client_name": "My MCP Client",
  "redirect_uris": ["http://localhost:3000/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

authgate의 CIMD 처리:

```text
/authorize?client_id=https://app.example.com/oauth/client.json&...
  1. client_id가 URL 형식인지 감지 (HTTPS + path 포함)
  2. 해당 URL에서 메타데이터 JSON fetch
  3. 검증:
     - client_id 필드가 fetch한 URL과 정확히 일치
     - redirect_uri가 메타데이터의 redirect_uris에 포함
  4. 검증 성공 → 메모리에서 ClientModel 생성 → 플로우 진행
```

CIMD가 DCR을 대체하는 이유:

| 항목 | DCR | CIMD |
|------|-----|------|
| 서버 저장 | client_id를 DB에 저장 (누적) | **저장 없음** (on-demand fetch) |
| 멀티 서버 | 서버마다 다른 client_id | **모든 서버에서 동일 URL** |
| 멀티 파드 | 공유 DB 필요 | **공유 상태 없음** |
| 삭제/정리 | cleanup job 필요 | **불필요** |

보안 규칙:
- private/loopback IP 거부 (SSRF 방어)
- 타임아웃 3초, 응답 크기 10KB 제한
- **리다이렉트 차단**: CIMD fetch는 리다이렉트를 따르지 않음. 301/302 응답 시 즉시 거부
- **grant_types 제한**: `authorization_code`, `refresh_token`만 허용. 그 외(`client_credentials`, `device_code` 등) 거부
- **token_endpoint_auth_method 제한**: `none`만 허용 (public client 전제)
- **response_types 제한**: `code`만 허용
- 캐시 TTL 5분, 만료 시 re-fetch

### CIMD 조회 정책

`GetClientByClientID`는 authorize, token exchange, refresh, revoke 모든 경로에서 호출된다.
CIMD 클라이언트(URL 형식 client_id)는 **매 호출 시 캐시 기반으로 조회**한다.

```text
호출 시점별 동작:

/authorize
  → CIMD fetch (캐시 miss 시 HTTP 요청)
  → client_id 일치, redirect_uri, grant_types 전체 검증

/oauth/token (code exchange)
  → CIMD fetch (캐시 hit 가능)
  → client_id 존재 확인 + grant_types에 authorization_code 포함 확인

/oauth/token (refresh)
  → CIMD fetch (캐시 hit 가능)
  → client_id 존재 확인 + grant_types에 refresh_token 포함 확인
  → fetch 실패 시 invalid_client → refresh 거부

/oauth/revoke
  → CIMD fetch (캐시 hit 가능)
  → client_id 존재 확인
  → fetch 실패 시에도 RFC 7009에 따라 200 반환
```

### CIMD URL 소멸 시 동작

클라이언트가 메타데이터 URL을 내리면:

```text
1. 캐시 만료 전: 기존 캐시로 정상 동작
2. 캐시 만료 후: re-fetch 실패 → invalid_client
   → refresh 거부 (사용자는 재로그인 필요)
   → DB의 refresh_token은 갱신 불가 상태로 남음
   → 만료 후 cleanup이 자연 삭제
```

메타데이터 내용이 중간에 바뀐 경우:
- 캐시 만료 후 re-fetch 시 새 메타데이터 적용
- `redirect_uris` 변경: `/authorize` 시점에만 검증하므로 기존 토큰에는 영향 없음
- `grant_types` 변경: code exchange/refresh 시 재검증하므로 **영향 있음** (예: `refresh_token`이 빠지면 갱신 거부)

## 채널 정책

MCP는 Browser와 **같은 code flow를 쓰더라도 정책 채널은 별도**다.

```text
Browser path: /login -> /login/callback
MCP path:     /mcp/login -> /mcp/callback
```

상태 규칙:

```text
user.Status = active
  -> MCP 허용

user.Status = pending_deletion / disabled / deleted
  -> MCP 차단 (account_inactive)
```

MCP는 Device와 같은 "후속 로그인 채널"이다.
가입과 `pending_deletion` 복구는 Browser 채널에서만 처리한다.

## Resource Parameter

MCP에서 `resource`는 부가 옵션이 아니라, "이 토큰을 어느 MCP 서버에서 쓸 것인가"를 나타내는 식별자다.

```text
/authorize?...&resource=https://mcp.example.com
/oauth/token?...&resource=https://mcp.example.com
```

의미:

```text
이 access_token은 https://mcp.example.com resource에 대한 접근 용도다.
```

## 토큰 의미

MCP access_token 계약은 아래와 같다.

```text
access_token
  -> 특정 resource 용도
  -> MCP 서버는 자기 resource용 토큰만 수용
```

authgate는 authorize 단계와 token 단계 모두에서 같은 `resource`를 취급해야 한다.

```text
1. /authorize 요청의 resource를 auth_request에 저장
2. /oauth/token 요청의 resource와 auth_request.resource를 대조
3. 불일치하면 invalid_target 등으로 거부
4. access_token의 aud는 canonical resource로 발급
```

MCP 서버가 검증해야 하는 항목:

```text
1. JWT signature
2. iss = authgate issuer
3. exp = 만료 안 됨
4. aud 또는 동등한 resource 의미 = 내 canonical resource
```

즉 MCP 서버는 단순 JWT 검증기가 아니라,
**"이 토큰이 내 resource 용도인가?"** 를 확인하는 protected resource여야 한다.

## 상태 저장과 수명

authgate는 stateless access token만 발급하는 서버가 아니라, 상태를 가진 인증 게이트다.

```text
메모리
├─ 클라이언트 설정   : clients.yaml → 시작 시 로드
├─ CIMD 클라이언트  : URL에서 on-demand fetch (캐시)

DB
├─ auth_requests    : authorize/code 흐름의 단기 상태
├─ sessions         : 브라우저 세션
├─ refresh_tokens   : refresh rotation 상태
├─ users            : 사용자 상태
└─ identities       : upstream identity 연결
```

수명:

```text
클라이언트 설정
  -> 서버 프로세스 수명 (YAML에서 로드)

CIMD 클라이언트
  -> HTTP 캐시 수명 (요청마다 또는 캐시 만료 시 re-fetch)

auth_requests
  -> 짧은 상태 (authorize ~ code exchange)

sessions
  -> 세션 TTL 동안 유지

refresh_tokens
  -> 만료 또는 revoke 후 cleanup
```

`resource`는 `auth_request`와 함께 짧게 유지되는 단기 상태다.
code exchange가 끝나면 auth_request와 함께 정리된다.

## 에러 케이스

| 상황 | 에러 코드 | HTTP | 설명 |
|------|----------|------|------|
| 미등록 클라이언트 | `invalid_client` | 400 | YAML에 없고 CIMD fetch도 실패 |
| CIMD fetch 실패 | `invalid_client` | 400 | URL 접근 불가, 타임아웃, SSRF 차단 |
| CIMD client_id 불일치 | `invalid_client` | 400 | 메타데이터의 client_id가 fetch URL과 다름 |
| PKCE 없음 / plain | `invalid_request` | 400 | `S256` 필수 |
| redirect_uri 불일치 | `invalid_request` | 400 | 메타데이터의 redirect_uris에 포함되어야 함 |
| 미가입 사용자 | `account_not_found` | 403 | Browser에서 먼저 가입 필요 |
| 비활성 계정 | `account_inactive` | 403 | `pending_deletion`, `disabled`, `deleted` |
| auth code 발급 후 상태 변경 | `invalid_grant` | 400 | `/oauth/token` 시점에 최종 상태 재검사 |
| code_verifier 불일치 | `invalid_grant` | 400 | PKCE 검증 실패 |
| resource 검증 실패 | `invalid_target` 등 | 400 | authorize/token resource 불일치 또는 허용되지 않은 resource |

## 보안 요구사항

- PKCE `S256` 필수
- public client 기본 (`token_endpoint_auth_method = none`)
- CIMD redirect_uri는 메타데이터 문서의 redirect_uris와 정확히 일치해야 함
- CIMD fetch 시 SSRF 방어: private/loopback IP 거부, 타임아웃 3초, 크기 10KB 제한
- `user.Status = active`일 때만 MCP 토큰 발급
- `/authorize`와 `/oauth/token` 모두에 동일한 `resource` 파라미터를 포함
- authgate는 `auth_requests.resource`를 저장하고 token 교환 시 대조
- MCP access_token의 `aud`는 canonical resource로 발급
- refresh_token은 해시 저장 + rotation
- MCP 서버는 access_token을 모든 요청마다 검증
- MCP 서버는 `iss`, `exp`, signature뿐 아니라 `aud/resource`를 검증
- access_token은 URI query string에 넣지 않는다

예제 서버는 HTTP 기반 원격 MCP 서버의 샘플이며, transport 자체보다 protected resource 계약을 우선 설명한다.

## 다른 스펙 참조

| 참조 | 내용 |
|------|------|
| [Spec 001](001-signup.md) | 가입은 Browser 전용 |
| [Spec 002](002-browser-login.md) | Browser code flow와 공통되는 로그인 골격 |
| [Spec 003](003-device-login.md) | Device는 별도 grant와 별도 상태 저장을 사용 |
| [Spec 005](005-token-lifecycle.md) | refresh/revoke/JWKS 검증 공통 규칙 |
| [Spec 007](007-data-model.md) | `auth_requests`, `refresh_tokens` 스키마, 클라이언트 설정 |
