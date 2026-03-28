# Authgate 코드 품질 분석 보고서

## 🚨 핵심 문제 요약

| 항목 | 상태 | 심각도 |
|------|------|--------|
| 테스트 커버리지 | **0%** | 🔴 심각 |
| SRP 위반 | 다수 발견 | 🟠 높음 |
| 파일 크기 | oauth.go 719라인 | 🟡 주의 |
| HTML/비즈니스 로직 혼합 | 있음 | 🟠 높음 |

---

## 1. 단일 책임 원칙 (SRP) 위반

### 1.1 함수가 너무 많은 일을 함

#### `handleAuthorize` (oauth.go:35-110)
**현재 하는 일:**
- 파라미터 파싱/검증
- PKCE 검증
- redirect_uri 화이트리스트 체크
- 세션 쿠키 파싱
- 세션/사용자 DB 조회
- upstream 리다이렉트 결정
- 임시 저장소에 요청 저장

**개선안:**
```go
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
    params, err := s.validateAuthorizeParams(r)      // 검증만
    if err != nil {
        return s.handleAuthorizeError(w, err)
    }
    
    session, err := s.sessionStore.GetFromCookie(r)  // 세션만
    if err == nil {
        return s.showConsentPage(w, session, params)
    }
    
    return s.redirectToLogin(w, params)              // 리다이렉트만
}
```

#### `handleCallback` (oauth.go:276-363)
**Oracle 평가:** "clearest SRP violation in the codebase"

**현재 하는 일:**
- upstream callback 파싱
- state 디코딩
- 코드 교환
- user + identity 프로비저닝
- 세션 생성
- 쿠키 설정
- pending auth 상태 변경
- consent 페이지 표시 여부 결정
- fallback: auth code 생성 및 리다이렉트

**개선안:**
```go
type CallbackResult interface {
    NeedsConsent | CompletedRedirect | Error
}

// 서비스 레이어로 분리
func (s *UpstreamLoginService) CompleteCallback(code, state string) (CallbackResult, error) {
    // 모든 로직 처리 후 결과 반환
}

// 핸들러는 단순히 HTTP 매핑만
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
    result, err := s.upstreamService.CompleteCallback(...)
    // 결과에 따른 HTTP 응답만 처리
}
```

### 1.2 파일이 여러 책임을 가짐

| 파일 | 현재 책임 | 권장 분리 |
|------|-----------|-----------|
| **oauth.go (719라인)** | Authorization, Callback, Consent, Device Flow, 임시 저장소, HTML 렌더링 | `authorize_handler.go`, `callback_handler.go`, `consent_handler.go`, `device_handler.go`, `view_renderer.go` |
| **token.go (327라인)** | Token grants + Logout | `token_handler.go`, `session_handler.go` (logout 분리) |
| **storage/session.go** | Sessions + Auth codes + Refresh tokens | `session_repo.go`, `auth_code_repo.go`, `refresh_token_repo.go` |
| **storage/db.go** | Connection + User repo + Identity repo + HashToken | `db.go` (connection only), `user_repo.go`, `identity_repo.go` |

### 1.3 비즈니스 로직과 HTML 렌더링 혼합

**문제:** 인라인 HTML이 핸들러에 직접 포함됨

```go
// oauth.go 안에 50+ 라인의 HTML/CSS
w.Write([]byte(`<!DOCTYPE html>
<html>...`))
```

**해결책:**
- 이미 `templates/` 디렉토리 존재함
- 인라인 HTML 제거하고 템플릿 시스템 사용
- `internal/pages/` 패키지 생성하여 렌더링 분리

---

## 2. 테스트 커버리지

### 2.1 현재 상태

```
❌ *_test.go 파일: 0개
❌ 테스트 커버리지: 0%
❌ 테스트 명령: 없음
```

### 2.2 우선순위 테스트 영역

| 우선순위 | 영역 | 이유 |
|----------|------|------|
| 1 | `internal/tokens` | 보안 핵심, JWT 생성/검증 |
| 2 | `internal/http` handlers | OAuth flow 분기, 상태 전환 |
| 3 | PKCE 검증 로직 | 보안 필수 |
| 4 | Session 만료/검증 | 인증 상태 관리 |
| 5 | Database 쿼리 | 데이터 무결성 |

### 2.3 권장 테스트 구조

```
authgate/
  internal/
    tokens/
      manager_test.go          # JWT 생성/검증 테스트
    http/
      handlers_test.go         # 핸들러 테스트 (httptest 사용)
    storage/
      integration_test.go      # DB 통합 테스트
  tests/
    integration/
      oauth_flow_test.go       # 전체 flow 통합 테스트
      device_flow_test.go
```

### 2.4 먼저 테스트할 순수 함수들

```go
// 쉬운 테스트, 즉각적인 커버리지 향상
- joinScopes(scopes []string) string
- HashToken(token string) string
- generateState/parseState
- sha256Sum(data string) []byte
- containsScope(scopes []string, scope string) bool
- generateUserCode() string
- tokens.Manager.GenerateAccessToken/GenerateIDToken
```

---

## 3. 구체적인 리팩토링 권장사항

### 3.1 즉시 필요한 변경 (높은 우선순위)

#### A. HTTP 레이어 분리
```
internal/http/
  handlers/
    authorize.go      # 150라인 이하
    callback.go       # upstream 처리
    consent.go        # consent 페이지
    device.go         # device flow
    token.go          # token endpoint
  pages/
    renderer.go       # HTML 렌더링
  middleware/
    auth.go           # 인증 미들웨어
```

#### B. 서비스 레이어 도입
```go
// services/authorization_service.go
type AuthorizationService interface {
    BeginAuthorization(params AuthorizeParams) (*AuthRequest, error)
    CompleteCallback(code, state string) (*Session, error)
    ApproveConsent(reqID string, user User) (*TokenResponse, error)
}

// services/device_flow_service.go
type DeviceFlowService interface {
    CreateDeviceRequest(clientID, scope string) (*DeviceRequest, error)
    ApproveDeviceRequest(userCode string, user User) error
    PollForToken(deviceCode string) (*TokenResponse, error)
}
```

#### C. 저장소 인터페이스화
```go
// 현재: 직접 *storage.DB 사용
func (s *Server) handleToken(...) {
    s.db.GetAuthCode(...)  // 직접 의존
}

// 개선: 인터페이스 추출
type AuthCodeStore interface {
    GetAuthCode(ctx context.Context, code string) (*AuthCode, error)
    CreateAuthCode(ctx context.Context, code *AuthCode) error
    MarkAuthCodeUsed(ctx context.Context, id uuid.UUID) error
}

type TokenGenerator interface {
    GenerateAccessToken(user User, scopes []string) (string, error)
    GenerateIDToken(user User, nonce string) (string, error)
}
```

### 3.2 주의해야 할 부분

| 위험 영역 | 이유 | 해결책 |
|-----------|------|--------|
| `authRequests`, `deviceCodes` | 패키지 전역 변수, 테스트 간 상태 유출 | 테스트마다 초기화 또는 인터페이스로 추출 |
| `handleCallback` fallback | 비즈니스 로직이 콜백 핸들러에 숨겨짐 | 먼저 리팩토링 우선순위 |
| `client_secret` | 읽기만 하고 검증 안 함 | ClientAuthenticator 구현 필요 |

---

## 4. 작업 우선순위

### 단계 1: 빠른 테스트 추가 (0.5일)
1. 순수 함수 테스트 (joinScopes, HashToken 등)
2. Token generation 테스트
3. `httptest`로 핸들러 기본 테스트

### 단계 2: 구조 개선 (1-2일)
1. HTTP 핸들러 파일 분리
2. 서비스 레이어 도입
3. 저장소 인터페이스화
4. HTML → 템플릿 이동

### 단계 3: 완전한 테스트 커버리지 (1일)
1. 모든 핸들러 테스트
2. OAuth flow 통합 테스트
3. Device flow 통합 테스트

---

## 5. 결론

### 가장 심각한 3가지
1. **테스트 0%** - 버그 발견 불가, 리팩토링 위험
2. **oauth.go 719라인** - 유지보수 불가
3. **HTML/비즈니스 로직 혼합** - 변경 시 영향도 예측 불가

### 권장 조치
1. **즉시**: 순수 함수 테스트 추가 (쉬운 승리)
2. **단기**: HTTP 핸들러 분리
3. **중기**: 서비스 레이어 도입 및 전체 테스트 커버리지

**예상 소요 시간**: 2-3일

---

## Oracle 검토자 의견

> "The biggest SRP problem is that `internal/http` is not just an HTTP layer; it is also the auth orchestration layer, temporary state store, session manager, and HTML view layer."

> "The best path is to unit-test `internal/tokens` and `internal/http` first, and treat `internal/storage` as DB-backed integration tests."

> "The fallback path in `handleCallback` is especially risky; it hides flow-specific business decisions in a callback handler. Refactor that first."
