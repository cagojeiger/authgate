# Test 005: Upstream OIDC Provider

## 목적

`upstream.OIDCProvider`의 OIDC Discovery, 토큰 교환, UserInfo 조회가 올바르게 동작하는지 검증한다.

기존 테스트(001-004)는 전부 `FakeProvider`를 사용하므로, **실제 HTTP 호출 경로(Discovery → Token → UserInfo)가 전혀 검증되지 않는다.**
이 문서는 그 갭을 메우기 위한 테스트를 정의한다.

## 배경

커밋 `fe3e69a`에서 `GoogleProvider`/`MockProvider`가 OIDC Discovery 기반 `OIDCProvider`로 교체되었다.
이후 `OIDCProvider`는 `zitadel/oidc/v3/pkg/client/rp` (RelyingParty) 라이브러리 기반으로 리팩토링되었다.

### 현재 구조

```text
OIDCProvider
  ├─ rp.NewRelyingPartyOIDC()   → Discovery + oauth2.Config 자동 구성
  ├─ rp.AuthURL(state, rp)      → authorization URL 생성
  └─ Exchange(ctx, code)
       ├─ rp.CodeExchange()     → POST token_endpoint + id_token 검증
       ├─ rp.Userinfo()         → GET userinfo_endpoint + JSON 디코딩
       └─ oidc.UserInfo → upstream.UserInfo 매핑
```

### rp 라이브러리가 처리하는 것 (authgate 테스트 범위 밖)

- HTTP Content-Type, Authorization 헤더 설정
- oauth2 token exchange 프로토콜
- JSON 디코딩 (`oidc.UserInfo`는 JSON 태그 완비 + `oidc.Bool` 타입으로 AWS Cognito 호환)
- ID token 서명 검증 (JWKS 기반)
- userinfo subject 일치 검증

### authgate가 테스트해야 하는 것

- `OIDCProvider`가 rp 라이브러리를 올바르게 조합하는가
- `deriveProviderName`이 issuer URL에서 provider 이름을 올바르게 파생하는가
- `oidc.UserInfo` → `upstream.UserInfo` 매핑이 올바른가 (특히 `email_verified`)
- Discovery/토큰/UserInfo 실패 시 에러가 올바르게 전파되는가

## 해결된 버그: email_verified JSON 디코딩

이전 수동 구현에서 `upstream.UserInfo` 구조체에 JSON 태그가 없어서
`email_verified` 필드가 항상 `false`로 저장되는 버그가 있었다.

**수정**: rp 라이브러리의 `oidc.UserInfo` (JSON 태그 완비)를 사용하고,
`Exchange()` 내부에서 `bool(info.EmailVerified)` → `upstream.UserInfo.EmailVerified`로 매핑.
`oidc-map-002` 테스트가 이 수정의 회귀를 방지한다.

## 테스트 전략

`httptest.Server`로 fake OIDC IdP를 구축하여 `OIDCProvider`의 실제 HTTP 경로를 검증한다.
외부 IdP(Google 등)에 의존하지 않는다.

```text
테스트 구조:

httptest.Server (fake OIDC IdP)
  ├─ /.well-known/openid-configuration  → Discovery JSON
  ├─ /keys                              → JWKS (테스트 RSA 공개키)
  ├─ /token                             → code → access_token + signed id_token
  └─ /userinfo                          → Bearer token → UserInfo JSON

OIDCProvider
  └─ NewOIDCProvider(fakeServer.URL, ..., WithRPOptions(rp.WithHTTPClient(...)))
```

테스트 파일 위치: `internal/upstream/oidc_test.go`
빌드 태그: 불필요 (외부 의존 없음, `httptest.Server`만 사용)

### fake OIDC IdP 요구사항

rp 라이브러리가 ID token을 검증하므로, fake IdP는:
1. 테스트 RSA 키 쌍 생성
2. `/keys` 에서 공개키를 JWKS 형식으로 제공
3. `/token` 에서 비밀키로 서명한 id_token JWT 반환

## 테스트 리스트

### Discovery (NewOIDCProvider)

| ID | 시나리오 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `oidc-disc-001` | 정상 Discovery | 유효한 Discovery JSON | Provider 생성 성공 | `Name()` 반환, `AuthURL()` 동작 |
| `oidc-disc-002` | Discovery 서버 연결 불가 | 존재하지 않는 URL | 에러 반환 | `NewOIDCProvider`가 error |
| `oidc-disc-003` | Discovery 응답 비-200 | 500 응답 | 에러 반환 | HTTP 에러 전파 |

### Provider Name 파생 (deriveProviderName)

| ID | 시나리오 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `oidc-name-001` | Google issuer | `https://accounts.google.com` | `"google"` | 도메인 두 번째 파트 |
| `oidc-name-002` | localhost | `http://localhost:8082` | `"localhost"` | 단일 호스트 |
| `oidc-name-003` | Microsoft | `https://login.microsoftonline.com` | `"microsoftonline"` | 복잡한 도메인 |
| `oidc-name-004` | 잘못된 URL | `not-a-url` | `"unknown"` | url.Parse 실패 시 안전한 기본값 |

### AuthURL 생성

| ID | 시나리오 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `oidc-auth-001` | 정상 URL 생성 | `state="req-123"` | Discovery의 authorization_endpoint 기반 URL | client_id, redirect_uri, response_type=code, state 파라미터 포함 |

### Exchange — 전체 경로 (Token + UserInfo)

| ID | 시나리오 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `oidc-exchange-001` | 정상 교환 | 유효한 code | `UserInfo` 반환 | sub, email, name, picture 올바르게 매핑 |
| `oidc-exchange-002` | 토큰 엔드포인트 에러 | 401 응답 | 에러 반환 | rp 라이브러리 에러 전파 |
| `oidc-exchange-003` | UserInfo 엔드포인트 에러 | 토큰 성공 + userinfo 401 | 에러 반환 | 2단계 에러 전파 |

### UserInfo → upstream.UserInfo 매핑

| ID | 시나리오 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `oidc-map-001` | 전체 필드 매핑 | 모든 필드 포함 UserInfo | 모든 필드 올바르게 매핑 | sub, email, email_verified, name, picture |
| `oidc-map-002` | email_verified=true | `"email_verified": true` | `UserInfo.EmailVerified == true` | **email_verified 버그 수정 회귀 테스트 (핵심)** |
| `oidc-map-003` | email_verified=false | `"email_verified": false` | `UserInfo.EmailVerified == false` | false도 정상 매핑 |
| `oidc-map-004` | email_verified 누락 | 필드 없음 | `UserInfo.EmailVerified == false` | 기본값 처리 |
| `oidc-map-005` | picture 포함 | `"picture": "https://..."` | `UserInfo.Picture` 설정 | avatar_url 저장 연계 |

### 전체 통합

| ID | 시나리오 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `oidc-e2e-001` | 정상 전체 경로 | fake IdP 전체 구성 | Discovery → AuthURL → Exchange → UserInfo 반환 | 3단계 통합 |
| `oidc-e2e-002` | 다른 redirectURI로 여러 Provider | browser/mcp/device 각각 | 각 Provider의 redirectURI가 AuthURL에 포함 | main.go의 3개 Provider 패턴 검증 |

## 기존 테스트와의 관계

```text
기존 테스트 (001-004)           이 테스트 (005)
───────────────────────        ─────────────────────
FakeProvider                   OIDCProvider + httptest.Server
  → Go 구조체 직접 생성           → rp 라이브러리 → oidc.UserInfo → 매핑
  → 상태기계/채널/E2E 검증        → OIDC 프로토콜 연동 검증
  → 비즈니스 로직 커버리지         → 인프라 레벨 커버리지

두 레벨 모두 필요:
  FakeProvider: 비즈니스 테스트의 빠른 실행 (외부 I/O 없음)
  OIDCProvider: 실제 OIDC 연동이 깨지지 않음을 보장
```

## 우선순위

| 우선순위 | 테스트 | 이유 |
|---------|--------|------|
| **P0** | `oidc-map-002` (email_verified 매핑) | 버그 수정 회귀 방지 |
| **P0** | `oidc-e2e-001` (전체 경로) | OIDCProvider 기본 동작 검증 |
| **P0** | `oidc-disc-001` (정상 Discovery) | Provider 생성 기본 |
| **P1** | `oidc-exchange-001~003` (Exchange 에러) | 에러 전파 |
| **P1** | `oidc-map-001,003~005` (매핑) | 필드별 매핑 검증 |
| **P2** | `oidc-name-001~004` (이름 파생) | 순수 함수, 낮은 위험 |
| **P2** | `oidc-disc-002~003` (Discovery 에러) | 시작 시 실패 → 빠르게 발견 |
| **P2** | `oidc-auth-001` (AuthURL) | rp 라이브러리 위임, 낮은 위험 |
