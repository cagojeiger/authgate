# Spec 010: Mock IdP

## 개요

authgate의 E2E 테스트와 로컬 개발을 위한 Mock Identity Provider.
Google OAuth 2.0 / OpenID Connect를 시뮬레이션하며, 테스트 시나리오별로 다른 응답을 반환한다.

## 목적

```
1. httptest 기반 통합 테스트에서 사용 (go test 내부)
2. docker-compose E2E에서 독립 서비스로 사용 (cmd/mock-idp)
3. 동일 코드 공유 — internal/mockidp 패키지
```

## 설계 원칙

mock-idp는 authgate 내부 상태기계를 대신 구현하지 않는다.
역할은 **upstream identity provider 응답을 제어하는 것**이다.

```text
mock-idp가 제어하는 것
  - authorize redirect 성공/실패
  - token 교환 성공/실패
  - userinfo의 sub/email/name

mock-idp가 제어하지 않는 것
  - initial_onboarding_incomplete
  - reconsent_required
  - pending_deletion
  - disabled
  - deleted
```

이 내부 상태들은 authgate의 DB fixture와 서비스 테스트가 책임진다.

즉 mock-idp는:

```text
"어떤 upstream 사용자로 로그인되었는가"
"upstream이 성공/실패했는가"
```

를 만드는 도구이고,

```text
"그 사용자가 authgate 내부에서 어떤 상태인가"
```

는 authgate가 판단한다.

## Google OAuth 실제 스펙 대비

### Google이 제공하는 엔드포인트

| 엔드포인트 | Google URL | mock-idp 경로 |
|-----------|-----------|-------------|
| Discovery | `https://accounts.google.com/.well-known/openid-configuration` | `GET /.well-known/openid-configuration` |
| Authorization | `https://accounts.google.com/o/oauth2/v2/auth` | `GET /authorize` |
| Token | `https://oauth2.googleapis.com/token` | `POST /token` |
| UserInfo | `https://openidconnect.googleapis.com/v1/userinfo` | `GET /userinfo` |

### Google Authorization 요청/응답

**요청** (authgate → Google):
```
GET /o/oauth2/v2/auth
  ?client_id=GOOGLE_CLIENT_ID
  &redirect_uri=https://auth.example.com/login/callback
  &response_type=code
  &scope=openid email profile
  &state=authRequestID
```

**응답** (Google → authgate):
```
302 → redirect_uri?code=AUTHORIZATION_CODE&state=authRequestID
```

**mock-idp 구현**: 자동 승인. 파라미터 검증 없이 즉시 redirect.

### Google Token 교환 요청/응답

**요청** (authgate → Google):
```
POST /token
Content-Type: application/x-www-form-urlencoded

code=AUTHORIZATION_CODE
&client_id=GOOGLE_CLIENT_ID
&client_secret=GOOGLE_SECRET
&redirect_uri=https://auth.example.com/login/callback
&grant_type=authorization_code
```

**응답** (Google → authgate):
```json
{
  "access_token": "ya29.xxx",
  "expires_in": 3600,
  "token_type": "Bearer",
  "scope": "openid email profile",
  "id_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

**mock-idp 구현**: `code`에서 시나리오를 파생. 유효한 code면 access_token 반환.

### Google UserInfo 응답

**요청** (authgate → Google):
```
GET /userinfo
Authorization: Bearer ya29.xxx
```

**응답**:
```json
{
  "sub": "1234567890",
  "email": "user@gmail.com",
  "email_verified": true,
  "name": "홍길동",
  "picture": "https://lh3.googleusercontent.com/xxx",
  "given_name": "길동",
  "family_name": "홍",
  "locale": "ko"
}
```

**mock-idp 구현**: `code` 파라미터에 인코딩된 시나리오에 따라 다른 사용자 정보 반환.

## 시나리오 설계

mock-idp는 **authorization code에 시나리오를 인코딩**하여 다른 응답을 반환한다.

### code → 시나리오 매핑

```
authorize 요청의 state를 그대로 code에 포함:
  code = "mock-code-{scenario}-{state}"

token 교환 시 code에서 scenario를 추출:
  scenario = code에서 파싱
```

### 시나리오 목록

| 시나리오 | code prefix | UserInfo 응답 | 용도 |
|---------|-------------|-------------|------|
| `new-user` | `mock-code-new-` | sub: `new-sub-{random}` | 신규 가입 트리거 |
| `existing` | `mock-code-existing-` | sub: `existing-sub-001` | 기존 유저 로그인 |
| `conflict` | `mock-code-conflict-` | sub: `conflict-sub-999`, email: 기존 유저와 동일 | email_conflict (409) |
| `default` | 그 외 | sub: `mock-sub-default`, email: `mock@example.com` | 기본 동작 |
| `error` | `mock-code-error-` | — | Token 교환 시 500 반환 |
| `invalid` | — | — | 잘못된 code → 400 invalid_grant |

## 필수 시나리오 세트

mock-idp는 "항상 성공 서버"가 아니라,
**기본은 성공하고 필요 시 실패/충돌을 재현할 수 있는 서버**여야 한다.

| 분류 | 시나리오 | authorize | token | userinfo | 목적 |
|------|---------|----------|-------|----------|------|
| Happy path | `default` | success | success | 고정 기본 사용자 | 가장 단순한 로컬 성공 흐름 |
| Happy path | `existing` | success | success | 고정 sub/email | 기존 유저 브라우저/디바이스/MCP 로그인 |
| Happy path | `new-user` | success | success | 새 sub/email | Spec 001 신규 가입 진입 |
| Policy edge | `conflict` | success | success | 다른 sub + 기존과 같은 email | `email_conflict` 재현 |
| Upstream failure | `denied` | `error=access_denied` redirect | — | — | 사용자가 Google에서 취소 |
| Upstream failure | `token_error` | success | 500 `server_error` | — | upstream token 장애 |
| Upstream failure | `invalid_code` | success | 400 `invalid_grant` | — | code 교환 실패 |
| Upstream failure | `userinfo_error` | success | success | 500 또는 malformed JSON | userinfo 조회 실패 |

### 권장 기본값

```text
scenario 미지정
  -> default
  -> 항상 성공
```

이렇게 하면 authgate 서버를 띄우고 브라우저로 눌러보는 기본 데모가 가장 단순해진다.

## 스펙 커버리지 매핑

| mock-idp 시나리오 | 커버하는 authgate 스펙 |
|-------------------|------------------------|
| `default` | Spec 002 브라우저 로그인 happy path, Spec 003 Device happy path, Spec 004 MCP happy path |
| `existing` | Spec 002 기존 유저 auto-approve, Spec 003/004 후속 채널 로그인 |
| `new-user` | Spec 001 자동 가입, Spec 002 신규 브라우저 로그인 |
| `conflict` | Spec 001/002 `email_conflict` |
| `denied` | Spec 002/003/004 upstream 사용자 취소 처리 |
| `token_error` | Spec 001/002/003/004 upstream_error 처리 |
| `invalid_code` | Spec 002/004 code 교환 실패 처리 |
| `userinfo_error` | Spec 001/002/003/004 userinfo 실패 처리 |

ASCII로 보면:

```text
[mock-idp scenarios]
  ├─ default / existing / new-user
  │    -> 성공 경로
  │    -> 가입/브라우저/디바이스/MCP
  │
  ├─ conflict
  │    -> email_conflict
  │
  └─ denied / token_error / invalid_code / userinfo_error
       -> upstream 실패 경로
```

## 구현 우선순위

### Phase 1: 로컬 서버 구동 최소셋

| 엔드포인트 | 시나리오 |
|-----------|----------|
| `GET /authorize` | `default`, `existing`, `new-user` |
| `POST /token` | success |
| `GET /userinfo` | 기본 사용자 반환 |

목적:

```text
authgate + mock-idp를 실제로 띄워서
브라우저 로그인 / 디바이스 로그인 / MCP 로그인 기본 흐름 확인
```

### Phase 2: 회귀 테스트용 실패 시나리오

| 엔드포인트 | 시나리오 |
|-----------|----------|
| `GET /authorize` | `denied` |
| `POST /token` | `token_error`, `invalid_code` |
| `GET /userinfo` | `conflict`, `userinfo_error` |

목적:

```text
upstream 장애 / 취소 / 충돌 / malformed 응답을
의도적으로 재현
```

### Phase 3: httptest + docker-compose 공용화

```text
internal/mockidp
  -> 공통 handler

cmd/mock-idp
  -> 독립 서버 실행

internal/integration
  -> 같은 handler를 httptest로 재사용
```

### 기본 사용자 정보

```json
{
  "sub": "mock-sub-default",
  "email": "mock@example.com",
  "email_verified": true,
  "name": "Mock User",
  "picture": "https://example.com/mock-avatar.png"
}
```

## 기존 테스트 케이스와의 매핑

### Level 2: FakeProvider (service 테스트) — 변경 불필요

현재 `FakeProvider`는 HTTP 없이 하드코딩된 `UserInfo`를 반환한다.
이 테스트들은 mock-idp와 무관하게 유지된다.

| 테스트 파일 | FakeProvider 사용 | 매핑 시나리오 |
|-----------|----------------|-------------|
| `login_test.go` | sub: `google-sub-123` | 기존 유저 / 신규 가입 |
| `device_test.go` | sub: `device-sub-123` | Device 콜백 |
| `mcp_test.go` | sub: `mcp-sub-123` | MCP 콜백 |
| `account_test.go` | sub: `acct-sub-123` | 탈퇴/복구 |
| `e2e_extended_test.go` | sub: `e2e-sub` | 전체 사이클 |
| `browser_extended_test.go` | sub: `browser-ext-sub` | 재동의 |
| `device_extended_test.go` | sub별 다름 | Device 가드 |
| `mcp_extended_test.go` | sub별 다름 | MCP 가드 |

### Level 4: httptest 통합 — mock-idp 사용

| 테스트 | 현재 방식 | mock-idp 적용 후 |
|--------|---------|----------------|
| `BrowserFullFlow` | FakeProvider + 수동 callback 시뮬레이션 | mock-idp httptest → 자동 redirect |
| `NoPKCE_TokenExchangeFails` | 직접 /oauth/token 호출 | 변경 없음 (authgate 레벨) |
| `RefreshAfterLogin` | FakeProvider | mock-idp httptest |
| `SecondLogin_AutoApprove` | FakeProvider | mock-idp httptest |
| `DeviceConsumed_RePolling` | 직접 storage 조작 | 변경 없음 |

### Level 5: docker-compose E2E — mock-idp 서비스

| 시나리오 | 테스트 방법 | mock-idp 시나리오 |
|---------|-----------|-----------------|
| 신규 가입 + 약관 | 브라우저로 접속 | `new-user` |
| 기존 유저 로그인 | curl 스크립트 | `existing` |
| email 충돌 | curl | `conflict` |
| upstream 장애 | curl | `error` |
| Device flow 전체 | CLI 시뮬레이션 | `existing` |
| 탈퇴 → 복구 | curl | `existing` |
| 탈퇴 → 재가입 | curl | `new-user` |

## 구현 구조

```
internal/mockidp/
  mockidp.go        ← 핵심 로직 (핸들러, 시나리오 파싱)

cmd/mock-idp/
  main.go           ← 독립 서버 (docker-compose용)

internal/integration/
  server.go         ← httptest에서 mock-idp 핸들러 사용
```

## 엔드포인트 상세

### GET /authorize

```
입력:
  redirect_uri (필수)
  state (필수)
  mock_scenario (선택, 없으면 default)
  scope, client_id, response_type (무시)

응답:
  기본:
    302 → redirect_uri?code=mock-code-default-{state}&state={state}

  denied 시나리오:
    302 → redirect_uri?error=access_denied&state={state}
```

### POST /token

```
입력:
  code (필수)
  grant_type=authorization_code (검증)
  client_id, client_secret, redirect_uri (무시)

응답 (정상):
  200 {
    "access_token": "mock-access-{code}",
    "token_type": "Bearer",
    "expires_in": 3600
  }

응답 (token_error 시나리오):
  500 {"error": "server_error"}

응답 (invalid_code 시나리오):
  400 {"error": "invalid_grant"}
```

### GET /userinfo

```
입력:
  Authorization: Bearer mock-access-{code}

응답:
  code에서 시나리오 추출 → 해당 사용자 정보 반환

  200 {
    "sub": "{scenario-dependent}",
    "email": "{scenario-dependent}",
    "email_verified": true,
    "name": "Mock User",
    "picture": "https://example.com/avatar.png"
  }

  userinfo_error 시나리오:
    500 {"error": "server_error"}

  conflict 시나리오:
    200 {
      "sub": "conflict-sub-999",
      "email": "기존 사용자와 같은 이메일",
      "email_verified": true,
      "name": "Conflict User"
    }
```

### GET /.well-known/openid-configuration

```
응답:
  200 {
    "issuer": "{PUBLIC_URL}",
    "authorization_endpoint": "{PUBLIC_URL}/authorize",
    "token_endpoint": "{PUBLIC_URL}/token",
    "userinfo_endpoint": "{PUBLIC_URL}/userinfo",
    "jwks_uri": "{PUBLIC_URL}/keys",
    "scopes_supported": ["openid", "email", "profile"],
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code"]
  }
```

## authgate upstream.Provider 연결

현재 `MockProvider`는 mock-idp에 HTTP 요청을 보낸다:
- `AuthURL` → `mock-idp/authorize` 리다이렉트
- `Exchange` → `mock-idp/userinfo?code=X`

mock-idp 구현 후 `MockProvider.Exchange`를 수정하여 Google과 동일한 2단계 (token → userinfo) 흐름으로 변경:
1. `POST /token` → access_token 획득
2. `GET /userinfo` (Bearer access_token) → 사용자 정보

이렇게 하면 MockProvider가 GoogleProvider와 동일한 코드 경로를 타게 된다.

## docker-compose 설정

```yaml
mock-idp:
  build:
    context: .
    dockerfile: Dockerfile.mock-idp
  ports:
    - "8082:8082"
  environment:
    PORT: 8082
    PUBLIC_URL: http://localhost:8082
```

authgate 환경변수:
```yaml
UPSTREAM_PROVIDER: mock
MOCK_IDP_URL: http://mock-idp:8082        # Docker 내부
MOCK_IDP_PUBLIC_URL: http://localhost:8082  # 브라우저 접근용
```

## 다른 스펙 참조

| 참조 | 내용 |
|------|------|
| [Spec 002](002-browser-login.md) | 브라우저 로그인 플로우 (mock-idp가 Google 역할) |
| [Spec 003](003-device-login.md) | Device 플로우 (callback에서 mock-idp 사용) |
| [Spec 009](009-operations.md) | MOCK_IDP_URL, MOCK_IDP_PUBLIC_URL 환경변수 |
| [ADR-000](../adr/000-authgate-identity.md) | upstream.Provider 인터페이스 |
