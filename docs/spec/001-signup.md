# Spec 001: 브라우저 최초 가입 (자동 프로비저닝)

## 본질

이 스펙은 독립적인 "회원가입 기능"이 아니다.
**브라우저 로그인(Spec 002) 내부의 분기**로, 최초 로그인 시 자동으로 계정을 생성하는 서브플로우다.

```
사용자가 "가입"을 인식하지 않는다.
로그인했더니 처음이라 계정이 생긴 것이다.
```

**가입은 브라우저를 통해서만 가능하다.**
Spec 003(디바이스)과 004(MCP)는 이미 가입이 완료된 사용자의 후속 로그인 채널이다.

## 전제 조건

- 사용자가 Google 계정을 보유해야 함
- authgate에 유효한 IdP 설정이 되어 있어야 함
- authgate에서 zitadel은 내장 라이브러리다 (별도 서버가 아님)

## 관련 엔드포인트

| Method | Path | 처리 | 설명 |
|--------|------|------|------|
| GET | `/login/callback` | authgate | Google 코드 교환 → 신규/기존 판별 → 가입 처리 |
| GET | `/login/terms` | authgate | 약관 동의 페이지 표시 |
| POST | `/login/terms` | authgate | 약관 동의 + 연령 확인 처리 → 상위 플로우 복귀 |

가입은 `/login/callback` 내부에서 발생한다. 별도 가입 엔드포인트는 없다.

## 식별자 모델

```
핵심 식별자: provider + provider_user_id (Google sub)
부가 정보:   email, name (표시/편의용)
```

| 식별자 | 역할 | 불변? | 조회 기준? |
|--------|------|-------|-----------|
| `provider + provider_user_id` | 계정 연결의 유일한 기준 | 예 (Google sub는 변하지 않음) | **예** |
| `email` | 표시용, 약관 증적 | 아니오 (Google에서 변경 가능) | 아니오 |
| `name` | 표시용 | 아니오 | 아니오 |
| `users.id` (UUID) | authgate 내부 식별자 | 예 | 토큰의 `sub` 클레임 |

**동일 email, 다른 Google sub는 다른 사람이다.** email로 계정을 찾지 않는다.

## 플로우

```mermaid
sequenceDiagram
    participant U as 사용자
    participant AG as authgate
    participant G as Google
    participant DB as PostgreSQL

    Note over U,DB: 1. Google 인증 (상위 로그인 플로우에서 시작됨)
    AG->>G: token exchange (authorization code)
    G-->>AG: access_token + id_token
    AG->>G: GET /userinfo (또는 id_token 디코딩)
    G-->>AG: {sub, email, email_verified, name, picture}

    Note over U,DB: 2. 신규/기존 판별
    AG->>DB: SELECT FROM user_identities WHERE provider='google' AND provider_user_id=$sub
    alt ErrNotFound (신규 유저)
        Note over AG,DB: → 이 스펙의 가입 플로우 진입
    else 유저 있음
        Note over AG: → Spec 002 브라우저 로그인 계속
    else DB 오류
        AG-->>U: 500 internal_error (가입 시도 안 함)
    end

    Note over U,DB: 3. 계정 생성 (단일 트랜잭션)
    AG->>DB: BEGIN
    AG->>DB: INSERT users (status='active', terms_accepted_at=NULL)
    AG->>DB: INSERT user_identities (provider='google', provider_user_id=$sub)
    AG->>DB: COMMIT
    Note right of DB: 실패 시 둘 다 ROLLBACK. 고아 레코드 없음.

    Note over U,DB: 4. 약관 + 연령 확인 (토큰 발급 전 필수 게이트)
    AG-->>U: terms.html 표시
    Note right of U: ☑ 이용약관 + 개인정보처리방침 동의<br/>☑ 13세 이상 확인
    U->>AG: POST /login/terms
    AG->>DB: UPDATE users SET terms_version=$v, terms_accepted_at=NOW(), privacy_version=$pv, privacy_accepted_at=NOW()

    Note over U,DB: 5. 세션 생성 + 상위 플로우 복귀
    AG->>DB: INSERT sessions
    AG->>AG: Set-Cookie (authgate_session)
    AG->>AG: CompleteAuthRequest → 브라우저 로그인 플로우로 복귀
    Note over U,DB: → Spec 002 브라우저 로그인의 토큰 발급 단계로 이어짐
```

## 계정 상태와 약관의 관계

```
계정 생성 완료 ≠ 로그인 완료
약관 동의 완료 = 토큰 발급 가능
```

가입 직후 계정 상태:

| 시점 | users.status | terms_accepted_at | 토큰 발급 | 설명 |
|------|-------------|-------------------|----------|------|
| 3단계 직후 (DB 생성) | `active` | `NULL` | **불가** | 계정은 있지만 약관 미동의 |
| 4단계 완료 (약관 동의) | `active` | 설정됨 | **가능** | 완전한 활성 계정 |

**`terms_accepted_at IS NULL` 또는 `privacy_accepted_at IS NULL`인 `active` 계정 = `onboarding_complete = false` (가입 온보딩 미완료).**
`active`는 계정이 정지/삭제되지 않았다는 의미이지, 토큰 발급 가능을 뜻하지 않는다.
토큰 발급 조건: `onboarding_complete = true` ([ADR-000](../adr/000-authgate-identity.md) 불변식 I5 참조). 버전 일치도 포함한다.

### 가입 미완료 레코드 정리

사용자가 약관 페이지에서 이탈하면 `onboarding_complete = false`인 유저가 남는다.

- 이 유저가 **다시 로그인하면**: `GetUserByProviderIdentity` → 기존 유저 발견 → 약관 페이지 재표시 → 동의하면 완료
- **영구 이탈 시**: cleanup 정책으로 처리

```sql
-- onboarding cleanup 정책:
-- 생성 후 7일 경과 + onboarding 미완료 유저 삭제
DELETE FROM users
WHERE status = 'active'
  AND (terms_accepted_at IS NULL OR privacy_accepted_at IS NULL)
  AND created_at < NOW() - INTERVAL '7 days';
```

이 cleanup은 [Spec 006](006-account-lifecycle.md)의 deletion cleanup(pending_deletion → deleted)과 별개 lifecycle이다.

## 이메일 충돌 정책

| 상황 | 원인 | 처리 |
|------|------|------|
| 같은 email, 같은 Google sub | 기존 유저 재로그인 | 정상 (로그인 플로우) |
| 같은 email, 다른 Google sub | 다른 사람이 같은 이메일 사용 | `email_conflict` 에러 (409) |
| 다른 email, 같은 Google sub | Google에서 이메일 변경 | 기존 유저로 로그인 (sub 기준) |

`email_conflict`는 시스템 에러(500)가 아니라 **정책 충돌**(409)이다.
현재는 멀티 IdP를 지원하지 않으므로 발생 확률은 매우 낮다.

## 가입 시 생성되는 데이터

```
users:
  id:                  UUID (자동 생성) → 토큰의 sub 클레임
  email:               Google 이메일 (표시용)
  email_verified:      Google 검증 결과
  name:                Google 프로필 이름
  status:              'active'
  terms_version:       NULL (약관 동의 후 설정)
  terms_accepted_at:   NULL (약관 동의 후 설정)
  privacy_version:     NULL (개인정보 동의 후 설정)
  privacy_accepted_at: NULL (개인정보 동의 후 설정)

user_identities:
  user_id:          위 users.id
  provider:         'google'
  provider_user_id: Google sub (불변 식별자, 조회 기준)
  provider_email:   Google 이메일 (가입 시점 기록)
```

상세 스키마는 [Spec 007 데이터 모델](007-data-model.md)을 참조.

## 가입 조건

| 조건 | 충족 방법 | 미충족 시 |
|------|----------|----------|
| Google 인증 성공 | Google OAuth | 가입 불가 |
| DB 조회 성공 | PostgreSQL 정상 | 500 (가입 시도 안 함) |
| identity 미존재 | `ErrNotFound` | 기존 유저 → 로그인 플로우 |
| 이메일 미충돌 | `users.email` UNIQUE 통과 | 409 `email_conflict` |
| 약관 동의 | 체크박스 선택 | 약관 페이지 재표시 (200) |
| 연령 확인 (13세 이상) | 체크박스 선택 | 약관 페이지 재표시 (200) |

## 가입 제한

현재 authgate는 **자동 가입 (open signup)** 모델이다.
Google 인증에 성공하면 누구나 가입할 수 있다.

향후 가입 제한이 필요하면 (SHOULD):
- 이메일 도메인 제한
- 초대 코드
- 승인 모드

## 에러 케이스

| 상황 | 에러 코드 | HTTP | 설명 |
|------|----------|------|------|
| Google 인증 실패 (사용자 취소) | — | 302 | 앱의 redirect_uri로 `error=access_denied` |
| Google 서버 오류 | `upstream_error` | 500 | Google 연동 실패 |
| DB 오류 (유저 조회) | `internal_error` | 500 | 가입 시도 안 함 |
| 이메일 충돌 (같은 email, 다른 sub) | `email_conflict` | 409 | 정책 충돌 — 운영자 확인 필요 |
| 트랜잭션 실패 (user+identity) | `internal_error` | 500 | 전부 ROLLBACK, 고아 없음 |
| 약관 미동의 / 연령 미확인 | — | 200 | 약관 페이지 재표시 (에러 메시지 포함) |

## 감사 로그

| 이벤트 | 시점 | 필드 |
|--------|------|------|
| `auth.signup` | 계정 생성 직후 (약관 전) | user_id, ip |
| `auth.terms_accepted` | 약관 동의 완료 | user_id, terms_version, privacy_version, ip |

## 다른 스펙과의 관계

```
Spec 001 (가입)은 Spec 002 (브라우저 로그인)에서만 진입 가능하다.

Spec 002 (브라우저) ── /login/callback 내부에서 ──→ Spec 001 (가입)
                                                       ↓
                                                  가입 완료 후
                                                       ↓
                                              Spec 002 토큰 발급으로 복귀

Spec 003 (디바이스) ── 가입 완료된 사용자만 사용 가능
Spec 004 (MCP) ────── 가입 완료된 사용자만 사용 가능
```
