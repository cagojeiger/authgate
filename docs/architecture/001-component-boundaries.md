# Architecture 001: 컴포넌트 경계

## 개요

authgate의 내부 컴포넌트를 정의하고, 각 컴포넌트의 책임 범위와 의존 방향을 고정한다.
이 문서는 Go 패키지 구조의 근거가 된다.

## 최상위 경계: zitadel/oidc vs authgate

[ADR-001](../adr/001-adopt-zitadel-oidc.md)에서 확정된 책임 분리:

```text
zitadel/oidc (프로토콜 계층)         authgate (비즈니스 계층)
──────────────────────              ──────────────────────
/authorize 검증                     op.Storage 구현 (필수 22 + Device 2)
/oauth/token grant 처리             upstream IdP 연동
JWT 서명/발급 (RS256)               로그인 UI + 세션 관리
JWKS, Discovery 자동 생성           유저/계정 lifecycle
Device polling 상태머신             user.Status 기반 상태 검사
Refresh grant orchestration
```

zitadel이 대부분의 프로토콜 라우팅을 소유하고 (`/.well-known/*`, `/authorize`, `/oauth/*`),
authgate가 `op.Storage` 인터페이스로 데이터를 제공한다.
다만 authgate는 일부 메타데이터/보조 엔드포인트를 직접 제공할 수 있다
(`/.well-known/oauth-authorization-server`, `/oauth/register`, `/login`, `/device`, `/account` 등).

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
 │ /login   │    │ login      │   │ OIDC         │
 │ /login/* │    │ device     │   │ Discovery    │
 │ /device  │    │ account    │   │              │
 │ /device/*│    │ cleanup    │   │ code exchange│
 │ /account │    │            │   │ userinfo     │
 │ /health  │    └──┬──┬──┬───┘   └──────────────┘
 └──────────┘       │  │  │
                    │  │  │
        ┌───────────┘  │  └───────────┐
        v              v              v
 ┌────────────┐  ┌──────────┐  ┌──────────┐
 │  storage   │  │  pages   │  │  clock   │
 │            │  │          │  │          │
 │ op.Storage │  │ device   │  │ Now()    │
 │ 22 + Dev 2 │  │ result   │  └──────────┘
 │            │  └──────────┘
 │ users      │
 │ sessions   │
 │ tokens     │
 │ clients    │
 │ auth_reqs  │
 │ device     │
 │ audit      │
 └──────┬─────┘
        │
 ┌──────────┐
 │  idgen   │
 │          │
 │ NewUUID  │
 │ NewToken │
 └──────────┘
```

**핵심 구조**: `handler -> service -> storage/upstream` 조합과 `handler -> pages` 렌더링 분리.
service가 `user.Status`를 직접 switch하여 상태를 판정한다.
`clock`과 `idgen`은 service/storage가 사용하는 deterministic test seam이다.

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
| **원자성** | 가입(users+identities), 삭제(status+revoke), refresh rotation은 단일 TX |

storage는 비즈니스 상태 판정을 하지 않는다. 다만 예외적으로 refresh grant는 zitadel이 `TokenRequestByRefreshToken`만 호출하므로, storage 내부에서 user 조회 후 `user.Status` 기반 상태 검증을 수행해야 한다.

### 3. handler

zitadel이 소유하지 않는 HTTP 엔드포인트를 처리한다. **얇은 HTTP 바인딩 계층**이다.

| 항목 | 설명 |
|------|------|
| **책임** | HTTP 요청/응답 바인딩, 쿠키/세션 처리, service 호출 |
| **스펙 근거** | [Spec 002](../spec/002-browser-login.md), [003](../spec/003-device-login.md), [004](../spec/004-mcp-login.md), [006](../spec/006-account-lifecycle.md) |
| **의존** | service |
| **엔드포인트** | `/login`, `/login/callback`, `/device`, `/device/approve`, `/device/auth/callback`, `/mcp/login`, `/mcp/callback`, `/account`, `/health`, `/ready` |

handler는 **HTTP를 파싱하고 service에 위임**한다. 비즈니스 로직을 직접 수행하지 않는다.

### 4. service

비즈니스 orchestration 계층. handler에서 분리된 핵심 로직을 담당한다.

| 항목 | 설명 |
|------|------|
| **책임** | 로그인 조율 (upstream 호출 → user 조회/생성 → user.Status 직접 판정 → 세션/로그인 완료 상태), Device 승인, 계정 삭제, cleanup |
| **스펙 근거** | Spec 001~006 전체 플로우 |
| **의존** | storage, upstream, clock |
| **파일** | `login.go`, `device.go`, `account.go`, `cleanup.go` |

service가 존재하는 이유:
- handler는 HTTP 바인딩만 담당 → handler 테스트 = HTTP 경로/응답 검증
- service는 비즈니스 전이 담당 → service 테스트 = 실DB + fixed clock으로 상태 전이 검증
- handler에 로직이 몰리면 HTTP 테스트가 너무 무거워진다

service는 **HTML을 직접 렌더링하지 않는다.**
service는 `ActionAutoApprove`, `DeviceShowApprove` 같은 결과를 반환하고,
handler가 이를 해석해 pages 템플릿을 렌더링하거나 redirect를 수행한다.

### 5. upstream

외부 IdP에 대한 프록시를 구현한다. OIDC Discovery를 통해 엔드포인트를 자동으로 탐지한다.

| 항목 | 설명 |
|------|------|
| **책임** | authorization URL 생성, authorization code → token 교환, userinfo 조회 |
| **스펙 근거** | [ADR-000](../adr/000-authgate-identity.md) IdP 정책, [Spec 002](../spec/002-browser-login.md) 4~5단계 |
| **의존** | config (OIDC credentials), HTTP client |
| **인터페이스** | `Provider` (3메서드: `Name`, `AuthURL`, `Exchange`) |
| **구현체** | `OIDCProvider` (OIDC Discovery 기반, zitadel/oidc v3 사용) |

upstream은 **authgate의 유저/세션을 모른다.** code를 교환하고 userinfo를 반환할 뿐이다.
service가 userinfo를 받아 storage에서 유저를 조회/생성한다.

### 6. pages

HTML 템플릿을 렌더링한다.

| 항목 | 설명 |
|------|------|
| **책임** | 디바이스 코드 입력, 디바이스 승인, 결과 페이지 렌더링 |
| **스펙 근거** | [Spec 008](../spec/008-pages.md) 페이지 목록 |
| **의존** | 없음 (Go html/template) |
| **원칙** | CSS 인라인, 외부 의존성 없음, 반응형, 시맨틱 HTML |

### 7. clock

시간 소스를 추상화한다. **mock이 아니라 deterministic test seam**이다.

| 항목 | 설명 |
|------|------|
| **책임** | 현재 시각 제공 |
| **인터페이스** | `Clock` (1메서드: `Now() time.Time`) |
| **구현체** | `RealClock` (프로덕션: `time.Now()`), `FixedClock` (테스트: 고정/진행 가능 시각) |
| **의존** | 없음 |
| **사용처** | service (cleanup 판정), storage (expires_at 비교, TTL 계산) |

시간 의존이 많은 로직: auth_request/device_code 만료, refresh_token TTL, deletion_scheduled_at. `time.Now()` 직접 호출 대신 `clock.Now()`를 사용하면 테스트에서 시간을 제어할 수 있다.

### 8. idgen

ID와 토큰을 생성한다. 테스트에서 **예측 가능한 값**을 만들기 위한 seam이다.

| 항목 | 설명 |
|------|------|
| **책임** | UUID, opaque token 생성. device_code/user_code는 zitadel이 자체 생성하므로 idgen 범위 밖. |
| **인터페이스** | `IDGenerator` (메서드: `NewUUID`, `NewOpaqueToken`) |
| **구현체** | `CryptoGenerator` (프로덕션: crypto/rand), `SequentialGenerator` (테스트: 예측 가능한 순차 값) |
| **의존** | 없음 |
| **사용처** | storage (session_id, token_id, refresh_token 생성) |

프로덕션에서는 128bit+ 엔트로피를 보장하고, 테스트에서는 `token-1`, `token-2` 같은 순차 값으로 assertion을 쉽게 한다.

## 의존 방향

```text
main → handler → service    (비즈니스 위임)
main → handler → pages      (HTTP 응답 렌더링)

service → storage            (DB 읽기/쓰기)
       → upstream           (IdP 교환)
       → clock              (현재 시각)

storage → clock             (TTL/만료 계산)
       → idgen              (ID/토큰 생성)

zitadel OP → storage        (op.Storage 인터페이스 호출)

config ← main               (시작 시 1회 로드)
       ← storage            (DB URL)
       ← upstream           (OIDC credentials)
       ← handler            (TTL 등)
```

**순환 의존 없음.** 모든 의존이 단방향이다.

핵심 규칙:
- `clock`, `idgen`은 외부 의존 없다 (인터페이스만 정의)
- `upstream`은 `storage`를 모른다
- `handler`는 HTTP 바인딩만 — 비즈니스 로직은 `service`
- `handler`가 HTML 렌더링을 담당하고 `pages`를 직접 호출한다
- `service`만 여러 컴포넌트를 조합하며, `user.Status`를 직접 switch하여 채널 접근을 판정한다

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
│   │   ├── models.go            # DB 모델 구조체
│   │   ├── pgarray.go           # PostgreSQL 배열 타입 헬퍼
│   │   ├── keys.go              # signing key 관리
│   │   ├── audit.go             # audit_log 기록
│   │   └── bcrypt.go            # bcrypt 해시 유틸리티
│   ├── service/
│   │   ├── login.go             # 로그인 orchestration (가입 포함)
│   │   ├── device.go            # Device 승인 orchestration
│   │   ├── account.go           # 계정 삭제/복구
│   │   └── cleanup.go           # 2종 cleanup (deletion/token)
│   ├── handler/
│   │   ├── login.go             # /login, /login/callback
│   │   ├── device.go            # /device, /device/approve, /device/auth/callback
│   │   └── account.go           # DELETE /account
│   │   # /health, /ready → cmd/authgate/main.go에 인라인
│   ├── upstream/
│   │   ├── provider.go          # Provider 인터페이스
│   │   └── oidc.go              # OIDC Discovery 기반 범용 Provider
│   ├── pages/
│   │   ├── renderer.go          # 템플릿 로드 + 렌더 함수
│   │   └── templates/           # HTML 파일
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
1. [zitadel] /authorize → storage.CreateAuthRequest(userID="")
2. [zitadel] → redirect /login?authRequestID=xxx
3. [handler] /login → service.HandleLogin()
4. [service] → storage.GetSession() → user.Status 확인
5. [service] 세션 없음 → upstream.AuthURL() → redirect IdP
6. [handler] /login/callback → service.HandleCallback()
7. [service] → upstream.Exchange() → userinfo
8. [service] → storage.GetUserByProviderIdentity()
9. [service] → user.Status switch (상태 검사)
10. [service] → 상태 결과에 따라:
      active → storage.CreateSession() → auth_request에 subject 연결 + 완료 상태 반영
      pending_deletion(browser) → storage.RecoverUser() (TX) → CreateSession
      disabled/deleted → 403
11. [zitadel] /oauth/token → storage.AuthRequestByCode() → subject 기준 최종 상태 재검사 → JWT 발급

## 실제 라이브러리 경계 주의

```text
/oauth/token (code)
  -> zitadel이 AuthRequestByCode(code)에서 subject를 읽어 토큰을 만든다.
  -> service는 auth code를 직접 발급하지 않는다.
  -> authgate는 storage.AuthRequestByCode 안에서 subject -> user를 재조회해
     `user.Status = active`인지 마지막으로 확인한다.
  -> 따라서 code 발급 후 pending_deletion / disabled / deleted로 바뀌면
     최종 응답은 invalid_grant다.

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
| **unit** | clock, idgen | 없음 | 없음 |
| **integration** | storage | 실 PostgreSQL (ephemeral) | 없음 |
| **integration** | service | 실 PostgreSQL + FixedClock + SequentialIDGen + fake OIDCProvider | upstream만 fake |
| **e2e** | handler + zitadel OP | 실 PostgreSQL + fake IdP server | 외부 IdP만 fake |

mock 최소화 원칙:
- repository mock 없음 — storage는 항상 실 DB
- HTTP client mock 없음 — upstream은 fake IdP 서버로 대체
- 시간/랜덤만 deterministic seam으로 제어

## 스펙 ↔ 컴포넌트 매핑

| 스펙 | 주요 컴포넌트 |
|------|-------------|
| Spec 001 (가입) | handler/login + service/login + storage/users + upstream |
| Spec 002 (브라우저 로그인) | handler/login + service/login + upstream |
| Spec 003 (Device 로그인) | handler/device + service/device + storage/device + pages |
| Spec 004 (MCP Authorization) | handler/login + service/login |
| Spec 005 (토큰 Lifecycle) | storage/tokens + clock |
| Spec 006 (계정 Lifecycle) | handler/account + service/account + service/cleanup + storage/users |
| Spec 007 (데이터 모델) | storage/* + migrations/ |
| Spec 008 (페이지) | pages/* |
| Spec 009 (운영) | config + storage/keys + service/cleanup |
