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
- **갱신**: 클라이언트가 refresh_token을 authgate `/token` 엔드포인트에 제출 → 새 access_token + 새 refresh_token 수신
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

authgate는 **OIDC 기반 인증 게이트웨이**이다. 현재 지원 IdP는 Google.

```
목적:    OIDC 호환 IdP를 통한 인증
현재:    Google OAuth (프로덕션), Mock IdP (개발용)
구조:    upstream.Provider 인터페이스 (2 메서드)
확장:    Apple, Kakao, GitHub 등 OIDC IdP 추가 가능 (~60줄/IdP)
제한:    동시 멀티 IdP 지원은 하지 않음 (MUST NOT)
```

IdP 추가는 `upstream.Provider` 인터페이스를 구현하면 된다.
단, **한 시점에 하나의 IdP만 운영**한다. "Google도 되고 Kakao도 되는" 멀티 IdP는
계정 연결(account linking), 중복 이메일 처리, IdP 선택 UI 등 복잡도가 급증하므로 범위 밖이다.

### authgate가 하는 것

| 영역 | 항목 |
|------|------|
| 인증 | OIDC IdP 로그인 (현재 Google) |
| 신원 | 로컬 user id + IdP subject 매핑 |
| 토큰 | access_token, refresh_token, id_token 발급/갱신/폐기 |
| 계정 | 상태 관리 + 삭제 (30일 유예 + PII 스크러빙) |
| 법적 | 약관 동의 기록, 연령 확인 |
| 검증 수단 | JWKS 엔드포인트 제공 (앱이 토큰 검증에 사용) |

### 계정 상태별 authgate 동작

`active`는 "정지/삭제되지 않은 계정"을 뜻한다. 토큰 발급 가능 여부는 `terms_accepted_at`도 함께 판단한다.

| 상태 | 브라우저 로그인 | CLI/MCP 로그인 | 토큰 갱신 | 설명 |
|------|-------------|--------------|----------|------|
| **active** (terms 완료) | 허용 | 허용 | 허용 | 완전한 정상 상태 |
| **active** (terms 미완료) | 허용 → 약관 표시 | 차단 (signup_required) | 차단 | 가입 온보딩 미완료 |
| **disabled** | 차단 | 차단 | 차단 | 관리자가 정지 |
| **pending_deletion** | 허용 → active 복구 | 차단 (account_inactive) | 차단 | 30일 유예. 브라우저만 복구 가능 |
| **deleted** | 차단 | 차단 | 차단 | PII 스크러빙 완료. 재가입만 가능 |

토큰 발급 조건: `status = 'active'` AND `terms_accepted_at IS NOT NULL` AND `privacy_accepted_at IS NOT NULL`

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
| **user_identities** | IdP 매핑 (Google sub ↔ 로컬 user) | 영구 (삭제 시 CASCADE) |
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
