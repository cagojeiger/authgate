# Architecture 001: 컴포넌트 경계

## 목적

authgate의 내부 구조, 책임 경계, 의존 방향을 정의한다.
이 문서는 "무엇이 공통 코어이고, 무엇이 채널 어댑터인지"를 명확히 하기 위한 기준 문서다.

핵심 목표는 두 가지다.

```text
1. authgate를 재사용 가능한 인증 서비스로 유지한다.
2. Browser / Device / MCP가 같은 인증 코어를 공유하는 어댑터 계층으로 정리한다.
```

설계 원칙은 [ADR-000](../adr/000-authgate-identity.md), 기술 선택은 [ADR-001](../adr/001-adopt-zitadel-oidc.md)을 따른다.

## 최상위 경계

### 1. zitadel/oidc vs authgate

```text
zitadel/oidc (프로토콜 계층)         authgate (비즈니스 계층)
──────────────────────              ──────────────────────
/authorize 검증                     op.Storage 구현
/oauth/token grant 처리             upstream IdP 연동
JWT 서명/발급 (RS256)               로그인/세션 orchestration
JWKS, Discovery 자동 생성           유저/계정 lifecycle
Device polling 상태머신             user.Status 정책
Refresh grant orchestration         pages / audit / cleanup
```

zitadel이 대부분의 표준 OAuth/OIDC 라우팅을 소유하고,
authgate는 `op.Storage`와 채널별 인증 UX를 제공한다.

### 2. Authentication vs Authorization

```text
Authentication
  - 사용자가 누구인지 확인
  - 세션 생성
  - 토큰 발급/갱신/폐기
  - 계정 상태에 따른 로그인 허용 여부 판단

Authorization
  - 이 토큰으로 무엇을 할 수 있는지 판단
  - role/permission/org/workspace/tool 권한
  - resource 내부 접근 통제
```

authgate는 Authentication만 책임진다.
Authorization은 consuming app, API, MCP server 책임이다.

`user.Status`는 authorization이 아니라 **인증 게이트 정책**이다.

### 3. OAuth 2.0 / OAuth 2.1 / 범위 밖 구분

이 문서에서는 표준 프로파일을 다음처럼 구분한다.

```text
OAuth 2.0
  - 전체 기반 프로토콜 계층
  - token, revocation, refresh, device grant의 기반

OAuth 2.1 스타일
  - Authorization Code + PKCE 중심
  - 브라우저와 MCP 채널에 적용되는 권장 프로파일

범위 밖
  - 현재 authgate의 코어 계약에 포함하지 않는 grant/endpoint/확장
```

#### 현재 authgate에 포함되는 것

| 분류 | 포함 항목 |
|------|-----------|
| OAuth 2.0 기반 | authorization endpoint, token endpoint, refresh token rotation, revocation, device authorization grant |
| OAuth 2.1 스타일 | Authorization Code + PKCE(S256) 중심 브라우저/MCP 로그인 프로파일, implicit/password 미사용 |
| OIDC | discovery, JWKS, id_token, userinfo |

#### 현재 authgate에서 별도 구분해야 하는 것

| 항목 | 설명 |
|------|------|
| Device Flow | RFC 8628 기반이며 OAuth 2.1의 브라우저 code flow와는 별도 채널 |
| MCP | OAuth 2.1 스타일 code + PKCE를 사용하지만, CIMD/resource 정책이 추가된 확장 채널 |

#### 현재 코어 계약에 포함하지 않는 것

아래 항목은 현재 authgate의 코어 구조에서 지원 대상으로 보지 않는다.

```text
grant type
  - implicit
  - resource owner password credentials
  - client credentials

dynamic client model
  - DCR (dynamic client registration)
  - PAR (pushed authorization requests)

introspection / resource-server authz
  - token introspection endpoint 기반 권한 판정
  - resource-level authorization policy
```

즉 authgate의 현재 표준 프로파일은 다음처럼 요약된다.

```text
core standard profile
  = OAuth 2.0 + OIDC 기반
  = browser/mcp에는 OAuth 2.1 스타일 code + PKCE 적용
  = device는 RFC 8628 extension
  = 권한 시스템/추가 grant 확장은 범위 밖
```

## 공통 코어

### 코어가 공유하는 것

아래 요소는 Browser / Device / MCP가 공통으로 공유하는 인증 코어다.

```text
Identity / Token Core
  - users / user_identities
  - sessions
  - refresh_tokens
  - auth_requests
  - device_codes
  - signing keys / JWKS
  - zitadel provider wiring
  - upstream OIDC exchange
  - account status policy
  - token issue / refresh / revoke
  - audit log
```

즉, authgate의 코어는 다음과 같이 정의한다.

```text
코어 = op.Storage 구현(토큰/인증 데이터) + 채널중립 인프라
```

코어 storage는 특정 채널의 URL/화면 흐름을 모른다.
채널별 로그인 흐름(browser/device/mcp)은 어댑터가 소유한다.
built-in adapter의 서비스 로직은 물리적으로 `internal/service` 패키지에 둘 수 있다.

### 코어/어댑터 책임 분할

| 영역 | 코어(storage/infra) | 채널 어댑터(service/handler) |
|------|----------------------|-------------------------------|
| 토큰 | 발급/갱신/폐기, refresh rotation | 채널별 토큰 진입 경로 연결 |
| 데이터 | users/sessions/refresh/auth_requests/device/audit 저장/조회 | 채널 입력 파싱, UX 흐름 |
| 서명/메타 | JWKS, discovery, 기본 AS metadata | 채널별 metadata 확장(MCP 등) |
| 로그인 | 채널중립 검증 훅/정책 seam | upstream IdP redirect/callback 오케스트레이션 |
| 세션 | session 저장/검증 primitive | 쿠키 발급/사용, 세션 경로 제어 |
| 가입/복구 | 데이터 업데이트 primitive | browser 채널에서 가입/복구 정책 적용 |
| 상태 정책 | 공통 정책 함수/검증 훅 | 채널별 allow/recover/deny 적용 |
| 운영 | cleanup, key loading, audit storage | 채널 액션에 대한 audit 이벤트 트리거 |

### 코어가 책임지지 않는 것

| 영역 | 항목 |
|------|------|
| 인가 | role, admin 여부, 조직/워크스페이스 권한 |
| 리소스 정책 | 특정 API/tool/resource 접근 허용 여부 |
| 앱 정책 | 약관, 결제 상태, 기능 플래그, 조직 정책 |

## 채널 어댑터

채널 어댑터는 코어를 사용해 특정 채널의 진입점과 UX를 제공한다.

```text
코어
  = 로그인 성공 후 무엇을 저장하고 어떤 토큰을 발급하는가

어댑터
  = 사용자가 어떤 채널로 들어와서 코어를 호출하는가
```

채널 어댑터는 두 종류로 나눈다.

```text
built-in adapter
  - 제품의 기본 채널
  - 항상 함께 배포되는 채널

optional adapter
  - 선택적으로 붙는 확장 채널
```

### Browser built-in adapter

```text
책임
  - /login
  - /login/callback
  - signup 허용
  - pending_deletion recover 허용
```

### Device built-in adapter

```text
책임
  - /device
  - /device/approve
  - /device/auth/callback
  - 디바이스 승인 UI
  - approve / deny orchestration
```

### MCP optional adapter

```text
책임
  - /mcp/login
  - /mcp/callback
  - CIMD
  - resource binding
  - MCP 전용 metadata 확장
```

즉 Browser도 Device도 코어 그 자체가 아니라 채널 어댑터다.
다만 Browser와 Device는 기본 제공 채널이므로 built-in adapter로 본다.
MCP는 코어 위에 붙는 선택적 확장 채널이므로 optional adapter로 본다.

## 엔드포인트 소유 규칙

엔드포인트는 다음 원칙으로 나눈다.

```text
표준 프로토콜 path = core
채널 진입/복귀 path = 각 adapter
```

### Core 엔드포인트

```text
/.well-known/openid-configuration
/.well-known/oauth-authorization-server
/authorize
/oauth/token
/oauth/revoke
/oauth/device/authorize
/keys
/userinfo
/end_session
```

### Adapter 엔드포인트

```text
Browser built-in adapter
  /login
  /login/callback

Device built-in adapter
  /device
  /device/approve
  /device/auth/callback

MCP optional adapter
  /mcp/login
  /mcp/callback
```

즉 경로가 다르더라도, 각 어댑터는 결국 같은 코어를 호출한다.

## 목표 구조

```text
                           +----------------------+
                           |   zitadel/oidc OP    |
                           | protocol engine      |
                           +----------+-----------+
                                      |
                                      v
┌──────────────────────────────────────────────────────────────┐
│                      authgate core                          │
│--------------------------------------------------------------│
│ users / sessions / tokens / auth_requests / device_codes     │
│ upstream OIDC / JWKS / refresh / revoke / account policy     │
└───────────────┬──────────────────────┬───────────────────────┘
                │                      │
                v                      v
       ┌────────────────┐     ┌────────────────┐
       │ Browser        │     │ Device         │
       │ built-in       │     │ built-in       │
       │ adapter        │     │ adapter        │
       └────────┬───────┘     └────────┬───────┘
                │                      │
                └──────────┬───────────┘
                           v
                  ┌────────────────────┐
                  │ MCP optional       │
                  │ adapter            │
                  └────────────────────┘
```

## 패키지 구조 목표

```text
cmd/authgate/
  main.go

internal/
  config/                   # 환경변수/설정 로딩

  service/                  # 채널별 비즈니스 로직 (built-in adapter 포함)
    access.go
    login.go
    device.go
    account.go
    cleanup.go

  handler/                  # HTTP 변환 (built-in adapter 포함)
    browser_login.go
    device.go
    account.go

  storage/                  # op.Storage 구현 (코어)
    storage.go
    auth_requests.go
    refresh_tokens.go
    device_codes.go
    users.go
    clients.go
    keys.go
    cleanup_runner.go

  db/                       # DB 접근 계층
    storeq/                 # sqlc 생성 코드
    queries/                # SQL 원본

  adapter/                  # optional adapter
    mcp/
      module.go
      handler.go
      service.go
      cimd.go
      policy.go
      metadata.go

  upstream/                 # 외부 IdP 연동
  pages/                    # HTML 템플릿 렌더링
    templates/
  clock/                    # 시간 추상화
  idgen/                    # ID/토큰 생성

  integration/              # 통합 테스트 (test only)
  testutil/                 # 테스트 헬퍼 (test only)

migrations/                 # DB 마이그레이션 SQL
```

구조 의도:

```text
storage
  - 공통 persistence
  - MCP 정책/검증을 몰라야 한다
  - 범용 필드(resource 등) 저장은 허용된다

service
  - flat 패키지 유지
  - 공통 인증 유스케이스 유지
  - browser/device는 built-in adapter가 호출
  - mcp는 optional adapter가 호출

adapter/mcp
  - MCP에서만 의미가 있는 흐름과 정책
```

## 데이터 흐름 예시

### Browser built-in adapter

```text
App -> /authorize
    -> /login
    -> /login/callback
    -> /authorize/callback
    -> /oauth/token
```

### Device built-in adapter

```text
CLI  -> /oauth/device/authorize
User -> /device
     -> /device/auth/callback
     -> /device/approve
CLI  -> /oauth/token
```

### MCP optional adapter

```text
Tool -> /authorize
     -> /mcp/login
     -> /mcp/callback
     -> /authorize/callback
     -> /oauth/token
```

세 채널 모두 결국 같은 코어의 저장소, 상태 정책, 토큰 발급 엔진을 공유한다.

## 테스트 전략

| 레벨 | 대상 | 의존성 | mock |
|------|------|--------|------|
| **unit** | clock, idgen | 없음 | 없음 |
| **unit** | service(access/login/device/account) | fake store + fake provider | DB 없음 |
| **integration** | storage | 실 PostgreSQL | 없음 |
| **integration** | service + OP | 실 PostgreSQL + fake IdP | upstream만 fake |

mock 최소화 원칙:

```text
repository mock 없음
storage는 가능하면 실 DB
시간/랜덤만 deterministic seam으로 제어
```

## 스펙 매핑

| 스펙 | 주요 컴포넌트 |
|------|-------------|
| Spec 001 (가입) | browser built-in adapter + storage/users + upstream |
| Spec 002 (브라우저 로그인) | browser built-in adapter + storage + upstream |
| Spec 003 (Device 로그인) | device built-in adapter + storage/device + pages |
| Spec 004 (MCP Authorization) | mcp optional adapter + storage/op.Storage seam |
| Spec 005 (토큰 Lifecycle) | storage(op.Storage) + clock |
| Spec 006 (계정 Lifecycle) | account built-in adapter + cleanup + storage/users |
| Spec 007 (데이터 모델) | storage/* + migrations/ |
| Spec 008 (페이지) | pages/* |
| Spec 009 (운영) | config + storage/keys + cleanup |
