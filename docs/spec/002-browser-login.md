# Spec 001: 브라우저 로그인 (Authorization Code + PKCE)

## 개요

웹 앱 사용자가 브라우저에서 Google 계정으로 로그인하고 access_token + refresh_token을 받는 플로우.

## 전제 조건

- 앱이 `oauth_clients` 테이블에 등록되어 있어야 함 (client_id, redirect_uri)
- authgate에 Google OAuth 자격증명이 설정되어 있어야 함 (GOOGLE_CLIENT_ID, GOOGLE_SECRET)
- 사용자가 Google 계정을 보유해야 함

## 표준

- OAuth 2.1 Authorization Code Grant
- RFC 7636 (PKCE, S256 필수)
- OpenID Connect Core 1.0

## 플로우

```mermaid
sequenceDiagram
    participant U as 사용자 브라우저
    participant App as 클라이언트 앱
    participant AG as authgate
    participant Z as zitadel OP
    participant G as Google

    Note over U,G: 1. 로그인 시작
    U->>App: 로그인 클릭
    App->>App: PKCE 생성 (code_verifier + code_challenge)
    App->>U: 302 Redirect to /oauth/authorize

    Note over U,G: 2. authgate → zitadel → 로그인 페이지
    U->>Z: GET /oauth/authorize?response_type=code&client_id=...&code_challenge=...
    Z->>Z: CreateAuthRequest (DB 저장)
    Z->>Z: client.LoginURL(authRequestID)
    Z->>U: 302 Redirect to /login?authRequestID=xxx

    Note over U,G: 3. 세션 확인
    U->>AG: GET /login?authRequestID=xxx
    alt 유효한 세션 쿠키 있음
        AG->>AG: getSessionUser → 유저 확인
        AG->>AG: 약관 확인 → 동의됨
        AG-->>U: 302 → OP callback (바로 완료)
    else 세션 없음
        AG->>U: 302 Redirect to Google
    end

    Note over U,G: 4. Google 인증
    U->>G: Google 로그인 화면
    G->>G: 사용자 인증 (비밀번호/생체 등)
    G->>U: 302 Redirect to /login/callback?code=google_code&state=authRequestID

    Note over U,G: 5. 유저 생성/조회
    U->>AG: GET /login/callback?code=...&state=...
    AG->>G: Exchange(google_code) → UserInfo
    G-->>AG: {sub, email, name}

    alt 신규 유저 (ErrNotFound)
        AG->>AG: CreateUserWithIdentity (트랜잭션)
        AG->>AG: audit: auth.signup
    else 기존 유저
        AG->>AG: audit: auth.login
    end

    alt pending_deletion 상태
        AG->>AG: CancelDeletion → active
        AG->>AG: audit: auth.deletion_cancelled
    end

    AG->>AG: CreateSession + Set-Cookie

    Note over U,G: 6. 약관 확인
    alt 약관 미동의
        AG->>U: terms.html (체크박스 2개)
        U->>AG: POST /login/terms (age_confirm=on)
        AG->>AG: AcceptTerms
        AG->>AG: audit: auth.terms_accepted
    end

    Note over U,G: 7. 토큰 발급
    AG->>AG: CompleteAuthRequest(authRequestID, userID)
    AG->>U: 302 → OP callback?id=authRequestID
    U->>Z: GET /callback?id=authRequestID
    Z->>Z: AuthRequestByID → Done=true
    Z->>Z: SaveAuthCode
    Z->>U: 302 → App redirect_uri?code=auth_code

    Note over U,G: 8. 코드 → 토큰 교환
    U->>App: code 전달
    App->>Z: POST /oauth/token (code + code_verifier + client_secret)
    Z->>Z: PKCE 검증 (S256)
    Z->>Z: client_secret 검증 (bcrypt)
    Z->>Z: JWT 서명 (RSA)
    Z-->>App: {access_token, refresh_token, id_token}

    Note over U,G: ✅ 완료
    App->>App: 토큰 저장
    App->>U: 로그인 성공
```

## 토큰 내용

```json
{
  "sub": "uuid-of-user",
  "iss": "https://auth.example.com",
  "aud": "my-app",
  "email": "kim@gmail.com",
  "name": "김철수",
  "scope": "openid profile email",
  "exp": 1234567890,
  "iat": 1234567000
}
```

## 에러 케이스

| 상황 | 응답 | HTTP |
|------|------|------|
| client_id 미등록 | `invalid_client` | 400 |
| redirect_uri 불일치 | `invalid_request` | 400 |
| PKCE 없음 | `invalid_request` | 400 |
| Google 인증 실패 | `upstream_error` | 500 |
| DB 오류 (유저 조회) | `internal_error` | 500 |
| 계정 비활성 (disabled) | `account_inactive` | 403 |
| 연령 미확인 | `invalid_request` | 400 |
| 만료된 auth request | 무시 (0 rows update) | — |

## 보안 요구사항

- PKCE S256 필수 (plain 불허)
- client_secret은 bcrypt 해시로 검증
- 세션 쿠키: HttpOnly, SameSite=Lax, Secure (프로덕션)
- access_token 수명: 15분 (기본)
- refresh_token: SHA-256 해시 저장, family_id로 rotation 추적
