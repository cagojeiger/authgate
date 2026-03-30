# Architecture 001: 컴포넌트 경계

## 개요

authgate의 내부 컴포넌트를 정의하고, 각 컴포넌트의 책임 범위와 의존 방향을 고정한다.
이 문서는 Go 패키지 구조의 근거가 된다.

## 최상위 경계: zitadel/oidc vs authgate

[ADR-001](../adr/001-adopt-zitadel-oidc.md)에서 확정된 책임 분리:

```text
zitadel/oidc (프로토콜 계층)         authgate (비즈니스 계층)
──────────────────────              ──────────────────────
/oauth/authorize 검증               op.Storage 구현 (필수 22 + Device 2)
/oauth/token grant 처리             upstream IdP 연동
JWT 서명/발급 (RS256)               로그인 UI + 세션 관리
JWKS, Discovery 자동 생성           유저/계정 lifecycle
Device polling 상태머신             DeriveLoginState / Guard
Refresh grant orchestration         약관/재동의 게이트
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
        ┌───────────────┼───────────────┐
        │               │               │
        v               v               v
 ┌──────────┐    ┌────────────┐   ┌──────────────┐
 │ handler  │    │  service   │   │   upstream   │
 │          │───>│            │   │              │
 │ /login   │    │ login      │   │ Google       │
 │ /login/* │    │ device     │   │ Mock         │
 │ /device  │    │ account    │   │              │
 │ /device/*│    │ cleanup    │   │ code exchange│
 │ /account │    │            │   │ userinfo     │
 │ /health  │    └──┬──┬──┬───┘   └──────────────┘
 └──────────┘       │  │  │
                    │  │  │
        ┌───────────┘  │  └───────────┐
        v              v              v
 ┌──────────┐   ┌────────────┐  ┌──────────┐
 │  guard   │   │  storage   │  │  pages   │
 │          │   │            │  │          │
 │ Derive   │   │ op.Storage │  │ terms    │
 │ LoginState│  │ 22 + Dev 2 │  │ device   │
 │ Guard    │   │            │  │ result   │
 │ Channel  │   │ users      │  └──────────┘
 └──────────┘   │ sessions   │
                │ tokens     │
 ┌──────────┐   │ clients    │
 │  clock   │   │ auth_reqs  │
 │          │   │ device     │
 │ Now()    │   │ audit      │
 └──────────┘   └──────┬─────┘
                       │
 ┌──────────┐          │
 │  idgen   │◄─────────┘
 │          │
 │ NewUUID  │
 │ NewToken │
 └──────────┘
```

**핵심 변경**: handler → service → storage/guard/upstream/pages 3계층 분리.
`clock`과 `idgen`은 service/storage가 사용하는 deterministic test seam.

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
| **인터페이스** | `op.Storage` (필수 22메서드) + `op.DeviceAuthorizationStorage` (2메서드) |
| **원자성** | 가입(users+identities), 삭제(status+revoke), 복구(status+session), refresh rotation — 모두 단일 TX |

storage는 기본적으로 **guard를 모른다.** 다만 예외적으로 refresh grant는 zitadel이 `TokenRequestByRefreshToken`만 호출하므로, storage 내부에서 user 조회 후 `DeriveLoginState`와 동등한 상태 검증을 수행해야 한다.

### 3. handler

zitadel이 소유하지 않는 HTTP 엔드포인트를 처리한다. **얇은 HTTP 바인딩 계층**이다.

| 항목 | 설명 |
|------|------|
| **책임** | HTTP 요청/응답 바인딩, 쿠키/세션 처리, service 호출 |
| **스펙 근거** | [Spec 002](../spec/002-browser-login.md), [003](../spec/003-device-login.md), [004](../spec/004-mcp-login.md), [006](../spec/006-account-lifecycle.md) |
| **의존** | service |
| **엔드포인트** | `/login`, `/login/callback`, `/login/terms`, `/device`, `/device/approve`, `/device/auth/callback`, `/account`, `/health`, `/ready` |

handler는 **HTTP를 파싱하고 service에 위임**한다. 비즈니스 로직을 직접 수행하지 않는다.

### 4. service

비즈니스 orchestration 계층. handler에서 분리된 핵심 로직을 담당한다.

| 항목 | 설명 |
|------|------|
| **책임** | 로그인 조율 (upstream 호출 → user 조회/생성 → guard → 세션/로그인 완료 상태), Device 승인, 계정 삭제, cleanup |
| **스펙 근거** | Spec 001~006 전체 플로우 |
| **의존** | storage, guard, upstream, pages, clock |
| **파일** | `login.go`, `device.go`, `account.go`, `cleanup.go` |

service가 존재하는 이유:
- handler는 HTTP 바인딩만 담당 → handler 테스트 = HTTP 경로/응답 검증
- service는 비즈니스 전이 담당 → service 테스트 = 실DB + fixed clock으로 상태 전이 검증
- handler에 로직이 몰리면 HTTP 테스트가 너무 무거워진다

### 5. guard

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
service가 storage/upstream 결과로 user를 얻은 뒤 guard에 넘겨 판정을 받는다.

### 6. upstream

외부 IdP (Google/Mock)에 대한 프록시를 구현한다.

| 항목 | 설명 |
|------|------|
| **책임** | authorization URL 생성, authorization code → token 교환, userinfo 조회 |
| **스펙 근거** | [ADR-000](../adr/000-authgate-identity.md) IdP 정책, [Spec 002](../spec/002-browser-login.md) 4~5단계 |
| **의존** | config (Google credentials), HTTP client |
| **인터페이스** | `Provider` (2메서드: `AuthURL`, `Exchange+Userinfo`) |
| **구현체** | `GoogleProvider`, `MockProvider` |

upstream은 **authgate의 유저/세션을 모른다.** code를 교환하고 userinfo를 반환할 뿐이다.
service가 userinfo를 받아 storage에서 유저를 조회/생성한다.

### 7. pages

HTML 템플릿을 렌더링한다.

| 항목 | 설명 |
|------|------|
| **책임** | 약관 동의, 디바이스 코드 입력, 디바이스 승인, 결과 페이지 렌더링 |
| **스펙 근거** | [Spec 008](../spec/008-pages.md) 페이지 목록 |
| **의존** | 없음 (Go html/template) |
| **원칙** | CSS 인라인, 외부 의존성 없음, 반응형, 시맨틱 HTML |

### 8. clock

시간 소스를 추상화한다. **mock이 아니라 deterministic test seam**이다.

| 항목 | 설명 |
|------|------|
| **책임** | 현재 시각 제공 |
| **인터페이스** | `Clock` (1메서드: `Now() time.Time`) |
| **구현체** | `RealClock` (프로덕션: `time.Now()`), `FixedClock` (테스트: 고정/진행 가능 시각) |
| **의존** | 없음 |
| **사용처** | service (cleanup 판정), storage (expires_at 비교, TTL 계산) |

시간 의존이 많은 로직: auth_request/device_code 만료, refresh_token TTL, deletion_scheduled_at, onboarding cleanup 7일. `time.Now()` 직접 호출 대신 `clock.Now()`를 사용하면 테스트에서 시간을 제어할 수 있다.

### 9. idgen

ID와 토큰을 생성한다. 테스트에서 **예측 가능한 값**을 만들기 위한 seam이다.

| 항목 | 설명 |
|------|------|
| **책임** | UUID, opaque token, device_code, user_code 생성 |
| **인터페이스** | `IDGenerator` (메서드: `NewUUID`, `NewOpaqueToken`, `NewDeviceCode`, `NewUserCode`) |
| **구현체** | `CryptoGenerator` (프로덕션: crypto/rand), `SequentialGenerator` (테스트: 예측 가능한 순차 값) |
| **의존** | 없음 |
| **사용처** | storage (session_id, token_id, refresh_token 생성), service (device_code 발급) |

프로덕션에서는 128bit+ 엔트로피를 보장하고, 테스트에서는 `token-1`, `token-2` 같은 순차 값으로 assertion을 쉽게 한다.

## 의존 방향

```text
main → handler → service    (비즈니스 위임)

service → guard             (상태 판정)
       → storage            (DB 읽기/쓰기)
       → upstream           (IdP 교환)
       → pages              (HTML 렌더링)
       → clock              (현재 시각)

storage → clock             (TTL/만료 계산)
       → idgen              (ID/토큰 생성)

zitadel OP → storage        (op.Storage 인터페이스 호출)

config ← main               (시작 시 1회 로드)
       ← storage            (DB URL)
       ← upstream           (Google credentials)
       ← handler            (TTL, 버전 등)
```

**순환 의존 없음.** 모든 의존이 단방향이다.

핵심 규칙:
- `guard`는 아무것도 의존하지 않는다 (순수 함수)
- `clock`, `idgen`도 외부 의존 없다 (인터페이스만 정의)
- `storage`는 `guard`를 모른다
- `upstream`은 `storage`를 모른다
- `handler`는 HTTP 바인딩만 — 비즈니스 로직은 `service`
- `service`만 여러 컴포넌트를 조합한다

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
│   │   └── audit.go             # audit_log 기록
│   ├── service/
│   │   ├── login.go             # 로그인 orchestration (가입 포함)
│   │   ├── device.go            # Device 승인 orchestration
│   │   ├── account.go           # 계정 삭제/복구
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
│   ├── pages/
│   │   ├── renderer.go          # 템플릿 로드 + 렌더 함수
│   │   └── templates/           # HTML 파일
│   │       ├── terms.html
│   │       ├── device_entry.html
│   │       ├── device_approve.html
│   │       └── result.html
│   ├── clock/
│   │   └── clock.go             # Clock 인터페이스 + RealClock
│   └── idgen/
│       └── idgen.go             # IDGenerator 인터페이스 + CryptoGenerator
└── migrations/
    └── 001_init.sql             # Spec 007 스키마
```

## 데이터 흐름 예시: 브라우저 로그인

```text
1. [zitadel] /oauth/authorize → storage.CreateAuthRequest(userID="")
2. [zitadel] → redirect /login?authRequestID=xxx
3. [handler] /login → service.HandleLogin()
4. [service] → storage.GetSession() → guard.DeriveLoginState()
5. [service] 세션 없음 → upstream.AuthURL() → redirect Google
6. [handler] /login/callback → service.HandleCallback()
7. [service] → upstream.Exchange() → userinfo
8. [service] → storage.GetUserByProviderIdentity()
9. [service] → guard.GuardLoginChannel(user, browser)
10. [service] → guard 결과에 따라:
      allow → storage.CreateSession() → auth_request에 subject 연결 + 완료 상태 반영
      show_terms → pages.RenderTerms()
      recover → storage.RecoverUser() (TX) → CreateSession
      inactive → 403
11. [zitadel] /oauth/token → storage.AuthRequestByCode() → SaveAuthCode/AuthRequest 기반으로 JWT 발급

## 실제 라이브러리 경계 주의

```text
/oauth/token (code)
  -> zitadel이 AuthRequestByCode(code)에서 subject를 읽어 토큰을 만든다.
  -> service는 auth code를 직접 발급하지 않는다.

/oauth/token (refresh)
  -> zitadel은 TokenRequestByRefreshToken(refreshToken)만 호출한다.
  -> 따라서 refresh 차단 정책은 storage 내부에서 user 상태를 직접 검증해야 한다.

Device approve
  -> authgate가 user_code에 대응하는 DeviceAuthorizationState.Subject를 채우고 Done=true로 만든다.
  -> 이후 polling/token issuance는 zitadel이 처리한다.
```
```

## 테스트 전략

| 레벨 | 대상 | 의존성 | mock |
|------|------|--------|------|
| **unit** | guard | 없음 | 없음 (순수 함수, table-driven) |
| **unit** | clock, idgen | 없음 | 없음 |
| **integration** | storage | 실 PostgreSQL (ephemeral) | 없음 |
| **integration** | service | 실 PostgreSQL + FixedClock + SequentialIDGen + MockProvider | upstream만 fake |
| **e2e** | handler + zitadel OP | 실 PostgreSQL + fake IdP server | 외부 IdP만 fake |

mock 최소화 원칙:
- repository mock 없음 — storage는 항상 실 DB
- HTTP client mock 없음 — upstream은 fake 서버 또는 MockProvider
- 시간/랜덤만 deterministic seam으로 제어

## 스펙 ↔ 컴포넌트 매핑

| 스펙 | 주요 컴포넌트 |
|------|-------------|
| Spec 001 (가입) | handler/login + service/login + storage/users + upstream + pages |
| Spec 002 (브라우저 로그인) | handler/login + service/login + guard + upstream + pages |
| Spec 003 (Device 로그인) | handler/device + service/device + guard + storage/device + pages |
| Spec 004 (MCP 로그인) | handler/login + service/login + guard |
| Spec 005 (토큰 Lifecycle) | storage/tokens + guard (refresh 가드) + clock |
| Spec 006 (계정 Lifecycle) | handler/account + service/account + service/cleanup + storage/users |
| Spec 007 (데이터 모델) | storage/* + migrations/ |
| Spec 008 (페이지) | pages/* |
| Spec 009 (운영) | config + storage/keys + service/cleanup |
