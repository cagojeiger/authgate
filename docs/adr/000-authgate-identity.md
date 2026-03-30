# ADR-000: authgate는 인증 경계이자 토큰 발급기다. 권한 시스템이 아니다.

## Status

Accepted (2026-03-29)

## 한 줄 정의

> authgate는 "이 사람이 누구인지" 확인하고 토큰을 발급한다. 그 이상은 하지 않는다.

## 목표

새 서비스는 authgate를 재사용하여 인증을 공통화한다. 서비스별 인증 구현은 하지 않는다.
새 서비스를 추가할 때 authgate 코드 변경은 0줄 — DB에 클라이언트 1개 등록하면 끝이다.
서비스는 어떤 언어/프레임워크든 상관없다. JWKS로 토큰을 검증하면 된다.

## Context

authgate는 여러 앱이 공유하는 중앙 인증 게이트웨이이다.
범위를 명확히 하지 않으면 권한 관리, 프로필 관리, 비즈니스 로직이 점진적으로 유입되어
작은 Keycloak이 아니라 **대충 만든 나쁜 Keycloak**이 탄생할 위험이 있다.

이 ADR은 authgate가 **무엇인지**, **무엇이 아닌지**, **앱과의 경계**를 확정한다.

## Decision

### authgate = 토큰 발급기

```
사용자 → authgate → "이 사람은 김철수(uuid)입니다. 여기 증명서(JWT)요."
                  → 앱: "감사합니다. 나머지는 제가 알아서 합니다."
```

### 3개 로그인 플로우, 동일한 토큰 계약

| 플로우 | 대상 | 방식 | 결과 |
|--------|------|------|------|
| 브라우저 로그인 | 웹 앱 | Auth Code + PKCE | access_token + refresh_token |
| Device 로그인 | CLI 도구 | RFC 8628 Device Code | access_token + refresh_token |
| MCP 로그인 | AI 도구 (Claude, Cursor 등) | OAuth 2.1 + PKCE | access_token + refresh_token |

세 플로우는 사용자 경험은 다르지만, authgate가 발급하는 **토큰의 기본 계약은 동일**하다.
앱은 로그인 방식이 아니라 토큰의 표준 클레임(sub, aud, exp, scope 등)만 신뢰한다.

### 토큰별 역할

| 토큰 | 발급 | 보관 | 용도 |
|------|------|------|------|
| **access_token** | authgate | 클라이언트 또는 앱 서버 | API 호출 시 `Authorization: Bearer` 헤더로 전달 |
| **id_token** | authgate | OIDC 클라이언트 | 로그인된 사용자 식별 확인용. API 호출에 사용하면 안 됨 |
| **refresh_token** | authgate | 신뢰 가능한 저장소 | 만료된 access_token 갱신 시 authgate에 제출. 앱이 직접 만들거나 검증하지 않음 |

### 플로우별 토큰 보관

| 토큰 | 브라우저 (웹 앱) | Device (CLI) | MCP (AI 도구) |
|------|----------------|-------------|--------------|
| **access_token** | 앱 서버 (세션/메모리) | 로컬 secure storage (`~/.config/`) | AI 도구 내부 메모리 |
| **id_token** | 프론트엔드 (사용자 표시용) | 보통 사용 안 함 | AI 도구가 사용자 확인용 |
| **refresh_token** | 앱 서버 (DB/세션) | 로컬 secure storage (`~/.config/`) | AI 도구 내부 storage |

토큰 lifecycle 전체가 authgate 책임이다:
- **발급**: authgate → 클라이언트
- **갱신**: 클라이언트가 refresh_token을 authgate `/oauth/token` 엔드포인트에 제출 → 새 access_token + 새 refresh_token 수신
- **회전**: authgate가 구 refresh_token 폐기 + 신 refresh_token 발급 (자동)
- **폐기**: 만료/revoke 시 authgate가 처리

### 토큰 클레임 — 최소 신원 원칙

authgate는 토큰에 **최소한의 신원 클레임만** 넣는다.

authgate는 **app-per-client 모델**을 사용하며, access_token의 `aud`는 대상 앱의 client_id로 발급한다.

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-uuid-123",
  "aud": "my-app",
  "exp": 1234567890,
  "iat": 1234567000,
  "scope": "openid profile email",
  "email": "kim@gmail.com",
  "name": "김철수"
}
```

`sub`는 필수 클레임이며, `email`과 `name`은 앱 통합 편의를 위해 제공하는 선택적 클레임이다.

**넣지 않는 것:**
- 앱별 권한 (role, is_admin)
- 구독/결제 상태 (plan, tier)
- 조직 역할 (org_role, workspace)
- 기능 플래그 (feature_x_enabled)

앱이 이런 정보가 필요하면 토큰의 `sub`로 자체 DB를 조회한다.

### IdP 정책

authgate는 **OIDC 기반 인증 게이트웨이**이다. 현재: OIDC Discovery 기반 단일 IdP 연동 (설정으로 Google, Mock 등 교체).

```
목적:    OIDC 호환 IdP를 통한 인증
현재:    OIDC Discovery 기반 단일 IdP 연동 (설정으로 Google, Mock 등 교체)
구조:    upstream.Provider 인터페이스 (3 메서드: Name, AuthURL, Exchange) + OIDC Discovery 자동 연동
확장:    OIDC Discovery 지원 IdP라면 OIDC_ISSUER_URL 변경만으로 교체 가능
제한:    동시 멀티 IdP 지원은 하지 않음 (MUST NOT)
```

IdP 추가는 `upstream.Provider` 인터페이스를 구현하면 된다.
단, **한 시점에 하나의 IdP만 운영**한다. "Google도 되고 Kakao도 되는" 멀티 IdP는
계정 연결(account linking), 중복 이메일 처리, IdP 선택 UI 등 복잡도가 급증하므로 범위 밖이다.

### authgate가 하는 것

| 영역 | 항목 |
|------|------|
| 인증 | OIDC IdP 로그인 (설정 기반) |
| 신원 | 로컬 user id + IdP subject 매핑 |
| 토큰 | access_token, refresh_token, id_token 발급/갱신/폐기 |
| 계정 | 상태 관리 + 삭제 (30일 유예 + PII 스크러빙) |
| 법적 | 약관 동의 기록, 연령 확인 |
| 검증 수단 | JWKS 엔드포인트 제공 (앱이 토큰 검증에 사용) |

### DeriveLoginState — 공식 로그인 상태 판정

authgate의 모든 채널 가드는 이 함수로 사용자 상태를 파생한다.
DB 컬럼이 아닌 **파생 판정**이며, `(status, terms_accepted_at, privacy_accepted_at, terms_version, privacy_version)` 5개 필드에서 계산한다.

```
DeriveLoginState(user):

1. if user.status in ('disabled', 'deleted'):
     → inactive

2. if user.status == 'pending_deletion':
     → recoverable_browser_only

3. if terms_accepted_at IS NULL OR privacy_accepted_at IS NULL:
     → initial_onboarding_incomplete

4. if terms_version != CURRENT_TERMS_VERSION
     OR privacy_version != CURRENT_PRIVACY_VERSION:
     → reconsent_required

5. → onboarding_complete
```

| 결과 | 의미 | cleanup 대상 |
|------|------|-------------|
| `inactive` | 정지/삭제된 계정 | 해당 없음 |
| `recoverable_browser_only` | 삭제 유예 중, 브라우저만 복구 가능 | deletion cleanup (30일) |
| `initial_onboarding_incomplete` | 가입 후 약관 동의 전 이탈 | onboarding cleanup (7일) |
| `reconsent_required` | 동의했으나 버전 변경됨, 재동의 필요 | **cleanup 비대상** (정상 유저) |
| `onboarding_complete` | 완전한 정상 상태 | 해당 없음 |

**`initial_onboarding_incomplete`와 `reconsent_required`는 다르다.**
- `initial_onboarding_incomplete`: `terms_accepted_at IS NULL`. 가입 후 이탈. 7일 cleanup 대상.
- `reconsent_required`: `terms_accepted_at IS NOT NULL`이지만 버전 불일치. 정상 유저. cleanup하면 안 된다.

### 세션의 의미

```
session   = authgate가 브라우저 사용자를 식별하는 진행 상태
refresh   = API 접근을 다시 얻는 권한
access    = 실제 API 호출 권한
```

session이 있어도 토큰이 없을 수 있다. 이는 정상이다:
- 신규 가입 직후 약관 동의 전
- 재동의 필요 (reconsent_required)
- pending_deletion 복구 후 auth_request 실패

### 계정 상태별 authgate 동작

| DeriveLoginState 결과 | 브라우저 | Device/MCP | 토큰 갱신 | 설명 |
|----------------------|---------|-----------|----------|------|
| `onboarding_complete` | 허용 | 허용 | 허용 | 정상 |
| `reconsent_required` | 허용 → 약관 재동의 | 차단 (signup_required) | 차단 | 버전 변경 |
| `initial_onboarding_incomplete` | 허용 → 약관 표시 | 차단 (signup_required) | 차단 | 최초 미동의 |
| `recoverable_browser_only` | 허용 → active 복구 | 차단 (account_inactive) | 차단 | 삭제 유예 |
| `inactive` | 차단 | 차단 | 차단 | 정지/삭제 |

### 공통 접근 표

| 엔드포인트 | onboarding_complete | reconsent / initial_incomplete | recoverable | inactive |
|-----------|-------------------|-------------------------------|------------|---------|
| GET `/login` | 허용 | 허용 | 허용(복구) | 차단 |
| GET `/login/callback` | 허용 | 허용 | 허용(복구) | 차단 |
| POST `/login/terms` | 허용 | 허용 | 허용(복구 중) | 차단 |
| POST `/oauth/token` (code) | 허용 | 차단 | 차단 | 차단 |
| POST `/oauth/token` (refresh) | 허용 | 차단 | 차단 | 차단 |
| POST `/oauth/device/authorize` | 허용 | 허용* | 허용* | 차단** |
| GET `/device` | 허용 | 허용* | 허용* | 차단 |
| POST `/device/approve` | 허용 | 차단 | 차단 | 차단 |
| DELETE `/account` | 허용 | 허용 | 멱등 | 차단 |
| GET `/.well-known/*` | 허용 | 허용 | 허용 | 허용 |

`*` Device 시작 자체는 허용하지만, approve/callback에서 DeriveLoginState를 검사한다.
`**` zitadel이 직접 처리하므로 authgate가 이 시점에서 상태 검사 불가. callback/approve 시점에서 차단한다.

### GuardLoginChannel — 공통 채널 가드

모든 로그인 채널(browser/device/mcp)의 진입 시점에서 `DeriveLoginState` 결과를 기반으로 판정한다.
Spec 002, 003, 004, 006에서 이 규칙을 참조한다.

```
GuardLoginChannel(user, channel):
  state = DeriveLoginState(user)

  if state == inactive:
    return account_inactive (403)

  if state == recoverable_browser_only:
    if channel == browser:
      return recover_then_continue
    else:
      return account_inactive (403)

  if state in (initial_onboarding_incomplete, reconsent_required):
    if channel == browser:
      return show_terms
    else:
      return signup_required (403)

  return allow  // onboarding_complete
```

### 계정 Lifecycle 사이클 규칙

authgate의 가입-사용-탈퇴-재가입 전체 사이클은 닫힌 구조다. 예외 경로는 없다.

```
[미가입]
  → 브라우저 가입만 가능 (Spec 001)
  → Device/MCP로는 가입 불가

[initial_onboarding_incomplete]
  → 브라우저만 계속 진행 가능 (약관 동의)
  → Device/MCP/refresh 불가
  → 7일 후 cleanup 대상

[onboarding_complete]
  → 모든 로그인 채널 허용
  → 약관 버전 변경 시 reconsent_required로 전이

[reconsent_required]
  → 브라우저만 재동의 가능
  → Device/MCP/refresh 불가
  → cleanup 비대상 (정상 유저)

[recoverable_browser_only] (pending_deletion)
  → 브라우저 로그인으로만 복구 가능
  → Device/MCP/refresh 불가
  → 30일 후 deleted로 전이

[inactive] (deleted)
  → 복구 불가. 재활성화 경로 없음.
  → 동일 IdP 계정으로 로그인해도 기존 계정으로 복구되지 않음.
  → user_identities가 삭제되어 ErrNotFound → Spec 001 신규 가입으로 재진입.
  → 새 user_id, 새 약관 동의, 이전 데이터와 무관.
```

이 사이클의 핵심 불변식:
1. **가입은 브라우저 전용.** Device/MCP에서 신규 가입은 발생하지 않는다.
2. **deleted는 종단 상태.** 어떤 로그인에서도 deleted → active 전이는 불가능하다.
3. **재가입은 신규 가입과 동일.** 이전 계정의 user_id, 데이터, 동의 기록과 연결되지 않는다.

### 앱의 JWT 검증 요구사항

앱은 authgate의 JWKS를 사용해 JWT 서명을 검증하며, 최소한 다음을 확인해야 한다:

- `iss` — authgate의 issuer URL과 일치하는가
- `aud` — 자신의 client_id와 일치하는가
- `exp` — 만료되지 않았는가
- 서명 — JWKS의 공개키로 RS256 검증

JWKS는 캐시하되 키 회전을 지원해야 한다. 검증 실패 시 fallback 없이 거부한다.

## authgate가 저장하는 데이터

| 데이터 | 목적 | 수명 |
|--------|------|------|
| **users** | 신원 (sub, email, name, status) | 영구 (삭제 시 PII 스크러빙) |
| **user_identities** | IdP 매핑 (IdP sub ↔ 로컬 user) | 영구 (삭제 시 CASCADE) |
| **sessions** | 로그인 상태 | 24시간 (기본) |
| **refresh_tokens** | 토큰 갱신 권한 (해시 저장) | 30일 (기본) |
| **oauth_clients** | 등록된 앱 (client_id, redirect_uri) | 영구 |
| **auth_requests** | 로그인 진행 중 상태 | 10분 (임시) |
| **device_codes** | CLI 로그인 진행 중 상태 | 5분 (임시) |
| **audit_log** | 운영 이벤트 (로그인, 가입, 탈퇴) | 보존 정책에 따름 |

## authgate가 저장하지 않는 데이터

| 데이터 | 이유 |
|--------|------|
| access_token | JWT — stateless, DB 저장 불필요 |
| 비밀번호 | Google에 위임. 직접 저장하지 않음 |
| 앱별 권한/역할 | 각 앱이 자체 DB에서 관리 |
| 유저 프로필 (주소, 전화번호 등) | 앱의 도메인 데이터 |
| 구독/결제 상태 | 앱의 비즈니스 데이터 |
| 기능 플래그 | 앱의 제품 데이터 |

## Non-Goals

authgate는 다음을 제공하지 않는다:

- 앱 공통 RBAC/ABAC
- 조직/워크스페이스 모델
- 사용자 프로필 편집 API
- 구독/결제 상태 관리
- 앱별 기능 플래그
- 사용자별 비즈니스 rate limit 정책
- 비밀번호/이메일 로그인
- MFA/OTP
- 멀티 IdP 동시 지원 (계정 연결, IdP 선택 UI), SAML, SCIM
- 동적 클라이언트 등록 (DCR)
- 제3자 앱 consent

## Decision Drivers

1. **토큰이 경계**: authgate는 토큰을 발급하고, 앱은 토큰을 해석한다. 토큰을 넘기는 순간 책임이 바뀐다.
2. **앱 독립성**: 각 앱은 자체 권한/비즈니스 로직을 소유한다. authgate에 의존하지 않는다.
3. **확장 불가 원칙**: 권한 관리, 프로필, 조직 기능이 authgate에 들어오면 안 된다.

## Consequences

### Positive
- authgate는 1,700줄 이하로 유지 가능
- 앱 추가 시 authgate 코드 변경 불필요 (클라이언트 등록만)
- 각 앱이 독립적으로 권한 체계를 설계 가능
- 3개 플로우가 동일한 토큰 계약 → 앱은 로그인 방식을 몰라도 됨

### Negative
- 앱마다 JWT 검증 로직을 구현해야 함 (JWKS 기반)
- "이 유저가 어떤 앱에 접근 가능한가"를 authgate가 모름 — 앱이 각자 판단
- 중앙 권한 관리가 없으므로 앱 간 권한 동기화는 앱의 책임
