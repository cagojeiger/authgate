# ADR-001: OAuth2/OIDC 구현에 zitadel/oidc v3 라이브러리 채택

## Status

Accepted (2026-03-28)

## Context

ADR-000에서 authgate의 정체성을 "인증 경계이자 토큰 발급기"로 정의했다.
이 ADR은 그 정체성을 구현하기 위한 **기술 선택**을 다룬다.

authgate는 OIDC 인증 게이트웨이로, 클라이언트에게는 OAuth2 서버 역할을 하면서
실제 인증은 upstream IdP에 위임하는 프록시 패턴을 사용한다.

OAuth2/OIDC 프로토콜은 RFC 6749, 7636, 8628 등 명확한 규약이 있으며,
직접 구현하면 규약 해석 오류가 보안 취약점으로 이어진다.
프로토콜 계층은 검증된 라이브러리에 위임하고, authgate는 비즈니스 로직에만 집중한다.

## Decision

`github.com/zitadel/oidc/v3` 라이브러리를 채택한다.

### 라이브러리가 처리하는 것

| 영역 | 내용 |
|------|------|
| Authorization endpoint | `/authorize` 요청 검증, PKCE, redirect_uri 확인 |
| Token endpoint | grant_type별 처리, code_verifier 검증, client_secret 대조 |
| JWT 서명/발급 | RS256 서명, jti/iss/aud/exp 클레임 구성 |
| JWKS | 공개키 직렬화, 스펙 정확성 보장 |
| OIDC Discovery | `/.well-known/openid-configuration` 자동 생성 |
| Device Flow | RFC 8628 상태 머신, polling 간격 관리 |
| Refresh Token 교환 | refresh grant 파싱/클라이언트 인증/rotation 흐름 호출 |

### authgate가 직접 처리하는 것

| 영역 | 내용 |
|------|------|
| `op.Storage` 구현 | zitadel 인터페이스(필수 23개 Health 포함, Device 포함 시 25개)를 PostgreSQL로 연결 |
| upstream IdP 연동 | OIDC IdP 코드 교환 → 유저 정보 취득 |
| 로그인 UI | 세션 확인, auto-approve |
| 유저/세션 관리 | 유저 생성, 세션 CRUD, 계정 삭제 |
| auth request 완료 | 로그인 완료 후 auth request에 subject를 연결하고 완료 상태를 만들기 |
| refresh 상태 검증 | refresh_token으로 user를 찾아 `user.Status` 기준 차단 여부 판정 |

### 왜 zitadel/oidc인가

| 기준 | zitadel/oidc v3 |
|------|----------------|
| OpenID 표준성 | RP basic/config profile 인증 명시, OP 구현 제공 |
| 프로덕션 사용성 | ZITADEL 생태계에서 실제 사용되는 라이브러리 |
| Device Flow | 공식 지원 (RFC 8628) |
| 유지보수 | 월간 릴리즈, Go 최신 버전 지원 |
| 임베드 가능 | pkg/op로 OP를 앱에 직접 내장. Storage 경계 명확 |
| Storage 인터페이스 | 필수 23개 (Health 포함), Device Flow 포함 시 25개 |

### 기각한 대안

| 대안 | 기각 사유 |
|------|----------|
| ory/fosite | 임베드 라이브러리로 쓸 때 학습/구성 부담이 크고, 우리 구조에는 과함 |
| dex / casdoor | 독립 서버라 임베드 불가. upstream 프록시 패턴과 불일치 |

## Consequences

### Positive
- 프로토콜 정확성이 라이브러리에 의해 보장됨
- authgate 코드가 비즈니스 로직에만 집중
- PKCE, client auth, JWKS 등 보안 필수 기능이 자동 처리
- RFC 업데이트는 라이브러리 버전 업으로 대응

### Negative
- zitadel이 대부분의 프로토콜 라우팅을 소유 (`/.well-known/*`, `/oauth/*` 중심)
- Storage 인터페이스 23개 (Health 포함, +Device 2개) 메서드 학습 필요
- 프로토콜 에러 시 라이브러리 내부 추적 필요

## 실제 코드 기준 경계 메모

`.repos/oidc` 기준으로 중요한 경계는 다음과 같다:

```text
1. CreateAuthRequest(ctx, authReq, userID)
   -> 일반 로그인 시작 시 userID는 빈 문자열일 수 있다.
   -> 로그인 완료 후 storage의 auth request row에 subject(userID)와 done 상태를 채운다.

2. /oauth/token (code)
   -> zitadel이 AuthRequestByCode(code)로 auth request를 읽고
      GetSubject()를 사용해 토큰을 만든다.
   -> authgate는 auth code를 직접 발급하는 것이 아니라,
      auth request가 완료 가능한 상태가 되도록 storage를 갱신한다.
   -> 또한 storage.AuthRequestByCode 안에서 subject -> user를 다시 조회해
      `user.Status = active`인지 최종 재검사한다.
      code 발급 후 상태가 바뀌었으면 `invalid_grant`로 차단한다.

3. /oauth/token (refresh)
   -> zitadel은 TokenRequestByRefreshToken(refreshToken)만 호출한다.
   -> RefreshTokenRequest 인터페이스에는 사용자 상태가 없으므로,
      authgate storage 구현이 refresh_token -> user 조회 -> 상태 검증을 직접 수행해야 한다.

4. Device Flow
   -> StoreDeviceAuthorization는 초기 pending state만 저장한다.
   -> approve 시점에 authgate가 Subject를 설정하고 Done=true로 바꿔야 한다.
```
