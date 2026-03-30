# Architecture 001: 컴포넌트 경계

## 개요

authgate의 내부 컴포넌트를 정의하고, 각 컴포넌트의 책임 범위와 의존 방향을 고정한다.
이 문서는 Go 패키지 구조의 근거가 된다.

## 최상위 경계: zitadel/oidc vs authgate

[ADR-001](../adr/001-adopt-zitadel-oidc.md)에서 확정된 책임 분리:

```text
zitadel/oidc (프로토콜 계층)         authgate (비즈니스 계층)
──────────────────────              ──────────────────────
/oauth/authorize 검증               op.Storage 구현 (28메서드)
/oauth/token grant 처리             upstream IdP 연동
JWT 서명/발급 (RS256)               로그인 UI + 세션 관리
JWKS, Discovery 자동 생성           유저/계정 lifecycle
Device Flow 상태머신                DeriveLoginState / Guard
Refresh Token 교환 판단             약관/재동의 게이트
```

zitadel이 HTTP 라우팅을 소유하고 (`/.well-known/*`, `/oauth/*`),
authgate가 `op.Storage` 인터페이스로 데이터를 제공한다.
authgate는 zitadel이 소유하지 않는 엔드포인트(`/login`, `/device`, `/account`)를 직접 처리한다.

## authgate 내부 컴포넌트

```text
┌──────────────────────────────────────────────────────┐
│                      main                             │
│  config 로드, DB 연결, zitadel OP 생성, 서버 시작       │
└───────────────────────┬──────────────────────────────┘
                        │
           ┌────────────┼────────────────┐
           │            │                │
           v            v                v
    ┌──────────┐  ┌────────────┐  ┌──────────────┐
    │ handler  │  │  storage   │  │   upstream   │
    │          │  │            │  │              │
    │ /login   │  │ op.Storage │  │ Google       │
    │ /login/  │  │ 28 methods │  │ Mock         │
    │ callback │  │            │  │              │
    │ /login/  │  │ users      │  │ code exchange│
    │ terms    │  │ sessions   │  │ userinfo     │
    │ /device  │  │ tokens     │  └──────────────┘
    │ /device/ │  │ clients    │
    │ approve  │  │ auth_reqs  │
    │ /account │  │ device     │
    │ /health  │  │ audit      │
    └────┬─────┘  └──────┬─────┘
         │               │
         v               │
    ┌──────────┐         │
    │  guard   │◄────────┘
    │          │
    │ Derive   │
    │ LoginState│
    │ Guard    │
    │ Channel  │
    └──────────┘
         │
         v
    ┌──────────┐
    │  pages   │
    │          │
    │ terms    │
    │ device   │
    │ result   │
    └──────────┘
```

## 컴포넌트별 책임

### 1. config

환경변수를 로드하고 유효성을 검증한다.

| 항목 | 설명 |
|------|------|
| **책임** | 환경변수 파싱, 기본값, DEV_MODE 강제, 타입 변환 |
| **스펙 근거** | [Spec 009](../spec/009-operations.md) 환경변수 표 |
| **의존** | 없음 (외부 의존 0) |
| **비고** | 구조체 1개로 전체 설정을 표현. 생성 시 검증 완료. |

### 2. storage

zitadel/oidc의 `op.Storage` + `op.DeviceAuthorizationStorage` 인터페이스를 PostgreSQL로 구현한다.

| 항목 | 설명 |
|------|------|
| **책임** | auth_requests, device_codes, tokens, clients, keys CRUD. users/sessions/audit CRUD. |
| **스펙 근거** | [ADR-001](../adr/001-adopt-zitadel-oidc.md) Storage 인터페이스, [Spec 007](../spec/007-data-model.md) 테이블 구조 |
| **의존** | `*sql.DB`, config (DB URL) |
| **인터페이스** | `op.Storage` (28메서드) + `op.DeviceAuthorizationStorage` |
| **원자성** | 가입(users+identities), 삭제(status+revoke), 복구(status+session), refresh rotation — 모두 단일 TX |

storage는 **guard를 모른다.** 상태 판정은 handler 레벨에서 수행한다.

### 3. handler

zitadel이 소유하지 않는 HTTP 엔드포인트를 처리한다.

| 항목 | 설명 |
|------|------|
| **책임** | 세션 확인, Google 코드 교환 조율, 약관 표시/처리, Device 승인, 계정 삭제 |
| **스펙 근거** | [Spec 002](../spec/002-browser-login.md), [003](../spec/003-device-login.md), [004](../spec/004-mcp-login.md), [006](../spec/006-account-lifecycle.md) |
| **의존** | storage, guard, upstream, pages |
| **엔드포인트** | `/login`, `/login/callback`, `/login/terms`, `/device`, `/device/approve`, `/device/auth/callback`, `/account`, `/health`, `/ready` |

handler는 **요청을 받으면 guard로 판정하고, storage로 상태를 변경하고, pages로 응답**한다.

### 4. guard

`DeriveLoginState`와 `GuardLoginChannel`을 구현한다.

| 항목 | 설명 |
|------|------|
| **책임** | 사용자 상태를 5가지 결과로 파생. 채널별 허용/차단 판정. |
| **스펙 근거** | [ADR-000](../adr/000-authgate-identity.md) DeriveLoginState, GuardLoginChannel |
| **의존** | 없음 (순수 함수, 사용자 데이터만 입력으로 받음) |
| **출력** | `inactive`, `recoverable_browser_only`, `initial_onboarding_incomplete`, `reconsent_required`, `onboarding_complete` |

```text
DeriveLoginState(user) → LoginState
GuardLoginChannel(user, channel) → GuardResult
```

guard는 **순수 판정 로직**이다. DB를 모르고, HTTP를 모른다.
handler가 storage에서 user를 조회한 후 guard에 넘겨 판정을 받는다.

### 5. upstream

외부 IdP (Google/Mock)에 대한 프록시를 구현한다.

| 항목 | 설명 |
|------|------|
| **책임** | authorization URL 생성, authorization code → token 교환, userinfo 조회 |
| **스펙 근거** | [ADR-000](../adr/000-authgate-identity.md) IdP 정책, [Spec 002](../spec/002-browser-login.md) 4~5단계 |
| **의존** | config (Google credentials), HTTP client |
| **인터페이스** | `Provider` (2메서드: `AuthURL`, `Exchange+Userinfo`) |
| **구현체** | `GoogleProvider`, `MockProvider` |

upstream은 **authgate의 유저/세션을 모른다.** code를 교환하고 userinfo를 반환할 뿐이다.
handler가 userinfo를 받아 storage에서 유저를 조회/생성한다.

### 6. pages

HTML 템플릿을 렌더링한다.

| 항목 | 설명 |
|------|------|
| **책임** | 약관 동의, 디바이스 코드 입력, 디바이스 승인, 결과 페이지 렌더링 |
| **스펙 근거** | [Spec 008](../spec/008-pages.md) 페이지 목록 |
| **의존** | 없음 (Go html/template) |
| **원칙** | CSS 인라인, 외부 의존성 없음, 반응형, 시맨틱 HTML |

## 의존 방향

```text
main → handler → guard      (판정 요청)
              → upstream    (IdP 교환)
              → storage     (DB 읽기/쓰기)
              → pages       (HTML 렌더링)

zitadel OP → storage        (op.Storage 인터페이스 호출)

config ← main               (시작 시 1회 로드)
       ← storage            (DB URL)
       ← upstream           (Google credentials)
       ← handler            (TTL, 버전 등)
```

**순환 의존 없음.** 모든 의존이 단방향이다.

핵심 규칙:
- `guard`는 아무것도 의존하지 않는다 (순수 함수)
- `storage`는 `guard`를 모른다
- `upstream`은 `storage`를 모른다
- `handler`만 여러 컴포넌트를 조합한다

## Go 패키지 매핑

```text
authgate/
├── cmd/
│   └── authgate/
│       └── main.go              # 진입점, 조립, 서버 시작
├── internal/
│   ├── config/
│   │   └── config.go            # 환경변수 → Config 구조체
│   ├── storage/
│   │   ├── storage.go           # op.Storage 구현 (zitadel 인터페이스)
│   │   ├── users.go             # users + user_identities CRUD
│   │   ├── sessions.go          # sessions CRUD
│   │   ├── tokens.go            # refresh_tokens CRUD + rotation
│   │   ├── clients.go           # oauth_clients 조회
│   │   ├── keys.go              # signing key 관리
│   │   ├── device.go            # device_codes CRUD
│   │   ├── audit.go             # audit_log 기록
│   │   └── cleanup.go           # 3종 cleanup (onboarding/deletion/token)
│   ├── handler/
│   │   ├── login.go             # /login, /login/callback, /login/terms
│   │   ├── device.go            # /device, /device/approve, /device/auth/callback
│   │   ├── account.go           # DELETE /account
│   │   └── health.go            # /health, /ready
│   ├── guard/
│   │   └── guard.go             # DeriveLoginState, GuardLoginChannel
│   ├── upstream/
│   │   ├── provider.go          # Provider 인터페이스
│   │   ├── google.go            # Google OAuth 구현
│   │   └── mock.go              # 개발용 Mock IdP
│   └── pages/
│       ├── renderer.go          # 템플릿 로드 + 렌더 함수
│       └── templates/           # HTML 파일
│           ├── terms.html
│           ├── device_entry.html
│           ├── device_approve.html
│           └── result.html
└── migrations/
    └── 001_init.sql             # Spec 007 스키마
```

## 데이터 흐름 예시: 브라우저 로그인

```text
1. [zitadel] /oauth/authorize → storage.CreateAuthRequest()
2. [zitadel] → redirect /login?authRequestID=xxx
3. [handler] /login → storage.GetSession() → guard.DeriveLoginState()
4. [handler] 세션 없음 → upstream.AuthURL() → redirect Google
5. [handler] /login/callback → upstream.Exchange() → userinfo
6. [handler] → storage.GetUserByProviderIdentity()
7. [handler] → guard.GuardLoginChannel(user, browser)
8. [handler] → guard 결과에 따라:
     allow → storage.CreateSession() → CompleteAuthRequest
     show_terms → pages.RenderTerms()
     recover → storage.RecoverUser() (TX) → CreateSession
     inactive → 403
9. [zitadel] /oauth/token → storage.AuthRequestByCode() → JWT 발급
```

## 스펙 ↔ 컴포넌트 매핑

| 스펙 | 주요 컴포넌트 |
|------|-------------|
| Spec 001 (가입) | handler/login + storage/users |
| Spec 002 (브라우저 로그인) | handler/login + guard + upstream + pages |
| Spec 003 (Device 로그인) | handler/device + guard + storage/device |
| Spec 004 (MCP 로그인) | handler/login (재사용) + guard |
| Spec 005 (토큰 Lifecycle) | storage/tokens + guard (refresh 가드) |
| Spec 006 (계정 Lifecycle) | handler/account + storage/users + storage/cleanup |
| Spec 007 (데이터 모델) | storage/* + migrations/ |
| Spec 008 (페이지) | pages/* |
| Spec 009 (운영) | config + storage/keys + storage/cleanup |
