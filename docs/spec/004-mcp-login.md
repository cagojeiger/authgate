# Spec 004: MCP 로그인 (Model Context Protocol OAuth 2.1)

## 개요

AI 도구 (Claude Desktop, Cursor 등)가 MCP 서버에 접근하기 위해 authgate에서 인증하고 access_token + refresh_token을 받는 플로우.
**사용자는 브라우저 가입(Spec 001)이 완료된 상태여야 한다.**

## 본질

MCP 로그인은 **브라우저 로그인(Spec 002)과 프로토콜이 동일**하다 (Auth Code + PKCE).
다른 점은 **목적**이다:

```
브라우저 로그인: "내가 직접 서비스를 쓰겠다"
MCP 로그인:     "AI 도구가 내 대신 서비스에 접근하겠다"
```

authgate 입장에서는 OAuth 2.1 / PKCE / 토큰 발급 코드는 브라우저와 공유하지만,
**로그인 진입 경로와 callback 경로는 MCP 전용으로 분리**한다.

```text
Browser: /login -> /login/callback
MCP:     /mcp/login -> /mcp/callback
```

따라서 `onboarding_complete`가 아닌 사용자는 MCP 토큰 발급 경로로 진입할 수 없다.
이 스펙은 MCP 특이사항만 다룬다.

## 전제

- authgate에서 zitadel/oidc는 **내장 라이브러리**다. 별도 서버가 아니다.
- MCP 클라이언트(AI 도구)가 OAuth 2.1을 지원해야 함
- authgate에 해당 MCP 클라이언트가 `oauth_clients`에 등록되어 있어야 함
- 해당 `oauth_clients.login_channel = 'mcp'` 여야 함
- **성공적으로 MCP 토큰을 발급받으려면** `DeriveLoginState = onboarding_complete`여야 함 (Spec 001 경유, [ADR-000](../adr/000-authgate-identity.md) 정의)
- 사용자가 브라우저 접근 가능해야 함

## 관련 엔드포인트

모든 경로는 authgate 주소 기준이다.

| Method | Path | 내부 처리 | 설명 |
|--------|------|----------|------|
| GET | `/.well-known/oauth-authorization-server` | zitadel 라이브러리 | RFC 8414 Discovery (MCP 클라이언트 우선 시도) |
| GET | `/.well-known/openid-configuration` | zitadel 라이브러리 | OIDC Discovery (fallback) |
| GET | `/oauth/authorize` | zitadel 라이브러리 | 인증 시작 (PKCE + resource 파라미터) |
| GET | `/mcp/login` | authgate 핸들러 | 세션 확인 → Google redirect |
| GET | `/mcp/callback` | authgate 핸들러 | Google 코드 교환 → 유저 조회 → auto-approve 또는 차단 |
| POST | `/oauth/token` | zitadel 라이브러리 | code + code_verifier → 토큰 발급 |
| GET | `/.well-known/jwks.json` | zitadel 라이브러리 | 공개키 |

## 표준

- OAuth 2.1 (IETF draft-ietf-oauth-v2-1)
- RFC 7636 (PKCE, S256 필수)
- RFC 8414 (OAuth Authorization Server Metadata)
- RFC 8707 (Resource Indicators) — MCP 클라이언트가 전송, authgate는 현재 무시
- MCP Spec 2025-03-26 Authorization

## Spec 002 (브라우저)와의 차이

| 항목 | 브라우저 (Spec 002) | MCP (이 스펙) |
|------|-------------------|-------------|
| **누가 쓰는가** | 사용자 본인 | AI 도구 (사용자 대리) |
| **신뢰 모델** | 사용자가 직접 조작 | 도구가 자동으로 API 호출 |
| **OAuth flow** | Auth Code + PKCE | Auth Code + PKCE (**동일**) |
| **Discovery** | `openid-configuration` | `oauth-authorization-server` (우선) → `openid-configuration` (fallback) |
| **추가 파라미터** | 없음 | `resource` (RFC 8707) |
| **클라이언트 유형** | confidential 또는 public | 보통 public (로컬 앱) |
| **redirect_uri** | 앱 서버 URL | `http://localhost:PORT/callback` |
| **revoke 시나리오** | 로그아웃 | "이 AI 도구 접근 취소" |
| **authgate 로그인 path** | `/login`, `/login/callback` | `/mcp/login`, `/mcp/callback` |

**OAuth / 토큰 발급 코드는 동일**하지만, 로그인 진입 경로와 채널 정책은 분리된다.

## 플로우

```mermaid
sequenceDiagram
    participant AI as AI 도구 (Claude/Cursor)
    participant AG as authgate
    participant U as 사용자 브라우저
    participant G as Google

    Note over AI,G: 1. Discovery
    AI->>AG: GET /.well-known/oauth-authorization-server
    AG-->>AI: {authorization_endpoint, token_endpoint, ...}
    Note right of AI: 실패 시 /.well-known/openid-configuration으로 fallback

    Note over AI,G: 2. 인증 시작
    AI->>AI: PKCE 생성 (code_verifier + code_challenge)
    AI->>U: 브라우저 열기 → authgate /oauth/authorize
    Note right of AI: ?response_type=code<br/>&client_id=claude-desktop<br/>&code_challenge=xxx<br/>&code_challenge_method=S256<br/>&resource=https://mcp-server.com<br/>&redirect_uri=http://localhost:PORT/callback<br/>&state=random

    Note over AI,G: 3. authgate MCP 로그인
    U->>AG: GET /oauth/authorize?...
    AG->>AG: [zitadel] client_id, redirect_uri, PKCE 검증
    AG->>AG: [zitadel] client.login_channel 확인
    AG->>AG: [zitadel] auth_request 생성
    AG->>U: 302 → /mcp/login?authRequestID=xxx

    U->>AG: GET /mcp/login?authRequestID=xxx
    alt 세션 있음 + DeriveLoginState = onboarding_complete
        AG->>AG: auto-approve → 5단계로
    else 세션 있음 + DeriveLoginState != onboarding_complete
        AG-->>U: 403 (GuardLoginChannel 결과: signup_required 또는 account_inactive)
        Note over AG: MCP는 Browser onboarding 채널이 아님
    else 세션 없음
        AG->>U: 302 → Google
        U->>G: Google 인증
        G->>U: 302 → /mcp/callback
        U->>AG: GET /mcp/callback?code=...&state=authRequestID
        AG->>AG: 기존 유저 확인 → DeriveLoginState + GuardLoginChannel(mcp)
        Note over AG: onboarding_complete일 때만<br/>세션 생성 + auth_request 완료 상태 반영 진행
        Note over AG: ErrNotFound → "브라우저에서 먼저 가입" 에러
    end

    Note over AI,G: 4. auth_request 완료 상태 반영
    AG->>AG: auth_request에 subject 연결 + 로그인 완료 상태 반영
    AG->>U: 302 → /oauth/callback → 302 → localhost:PORT/callback?code=auth_code&state=...

    Note over AI,G: 5. 토큰 교환 (AI 도구 ↔ authgate)
    U->>AI: code 전달 (localhost redirect)
    AI->>AG: POST /oauth/token (code + code_verifier, client_id)
    AG->>AG: [zitadel] PKCE S256 검증
    AG->>AG: [zitadel] JWT 서명 (RSA)
    AG-->>AI: {access_token, refresh_token}

    Note over AI,G: 6. MCP 서버 접근
    AI->>AI: Authorization: Bearer <access_token>
    Note over AI,G: ✅ AI 도구 인증 완료
```

## MCP 특이사항

### Discovery

MCP 클라이언트는 RFC 8414 (`oauth-authorization-server`)를 먼저 시도하고,
없으면 OIDC Discovery (`openid-configuration`)로 fallback한다.
zitadel/oidc가 둘 다 자동 제공하므로 authgate 추가 작업 없음.

### 채널 정책

MCP 로그인은 브라우저 창을 열지만, **경로와 정책 채널 모두 browser와 분리**된다.

```text
Browser path: /login, /login/callback
MCP path:     /mcp/login, /mcp/callback
```

따라서 다음 규칙을 따른다:

```text
DeriveLoginState = onboarding_complete
  -> allow

DeriveLoginState = initial_onboarding_incomplete
  -> signup_required

DeriveLoginState = reconsent_required
  -> signup_required

DeriveLoginState = recoverable_browser_only / inactive
  -> account_inactive
```

MCP는 Device와 동일하게 **후속 로그인 채널**이다.
가입, 재동의, pending_deletion 복구는 Browser 채널에서만 처리한다.

### Resource Indicator (RFC 8707)

```
MCP 클라이언트가 보내는 것:
  /oauth/authorize?...&resource=https://my-mcp-server.com

의미: "이 토큰을 my-mcp-server.com에서 사용할 것이다"

현재 authgate: resource 파라미터를 무시 (에러 없이 진행)
영향: 대부분의 MCP 클라이언트에서 동작함
향후: 클라이언트가 aud 검증을 시작하면 미들웨어로 대응 (~30줄)
```

### Dynamic Client Registration (DCR)

```
현재: 미지원 (MUST NOT — ADR-000 Non-Goals)
MCP spec: SHOULD (권장)
실질적 영향: MCP 클라이언트를 oauth_clients에 수동 등록. Spec 009 참조.
```

## 에러 케이스

| 상황 | 에러 코드 | HTTP | 설명 |
|------|----------|------|------|
| 미등록 클라이언트 | `invalid_client` | 400 | zitadel이 처리 |
| PKCE 없음 / plain | `invalid_request` | 400 | S256 필수 |
| redirect_uri 불일치 | `invalid_request` | 400 | localhost 또는 HTTPS만 |
| 가입 미완료 사용자 (`initial_onboarding_incomplete`) | `signup_required` | 403 | 브라우저 가입 먼저 필요 |
| 재동의 필요 사용자 (`reconsent_required`) | `signup_required` | 403 | 브라우저에서 먼저 재동의 필요 |
| Google 서버 오류 | `upstream_error` | 500 | Google 연동 실패 |
| 비활성/복구 필요 계정 | `account_inactive` | 403 | disabled/deleted/pending_deletion |
| resource 파라미터 | — | — | 무시 (에러 없음) |
| code_verifier 불일치 | `invalid_grant` | 400 | zitadel이 처리 |

## 보안 요구사항

- PKCE S256 필수 (MCP spec + OAuth 2.1 요구)
- redirect_uri: `http://localhost:*` 또는 HTTPS만 허용
- MCP 클라이언트는 보통 public client (client_secret 없음)
- access_token 수명: 15분 (MCP 세션 중 자동 갱신)
- refresh_token: 해시 저장 + rotation

## 알려진 제한

1. **RFC 8707 resource 미처리** — zitadel/oidc 이슈 오픈. MCP 클라이언트가 aud 검증 시작하면 미들웨어 추가 필요.
2. **DCR 미지원** — 클라이언트 수동 등록 (Spec 009). 소수 MCP 클라이언트면 충분.

## 다른 스펙 참조

| 참조 | 내용 |
|------|------|
| [Spec 001](001-signup.md) | 가입은 브라우저 전용. MCP에서 신규 가입 불가 |
| [Spec 002](002-browser-login.md) | 동일한 Auth Code + PKCE 플로우 (브라우저 경로와 정책만 다름) |
| [Spec 005](005-token-lifecycle.md) | AI 도구의 토큰 갱신 (15분마다 자동) |
| [Spec 009](009-operations.md) | MCP 클라이언트 등록 방법 |
