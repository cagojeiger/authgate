# Spec 008: authgate 페이지

## 개요

authgate가 직접 제공하는 HTML 페이지 목록.
이 페이지들은 토큰 발급 전 조건(디바이스 승인)을 처리하므로 authgate 책임이다.

약관/개인정보 동의는 **각 앱이 자체 관리**한다. authgate는 순수 인증 서비스이며, 약관 페이지를 제공하지 않는다.

## 페이지 목록

| 페이지 | URL | 용도 | 언제 표시되나 |
|--------|-----|------|-------------|
| 디바이스 코드 입력 | `/device` (GET) | user_code 입력 폼 | CLI 로그인 시 사용자가 브라우저에서 접근 |
| 디바이스 승인 | `/device?user_code=XXXX` (GET) | 승인/거부 선택 | user_code 입력 후 |
| 결과 | `/device/approve` (POST 결과) | 승인/거부 결과 표시 | 디바이스 승인/거부 후 |
| 에러 | 모든 에러 경로 | HTTP 에러 코드 + 메시지 표시 | 인증 실패, 잘못된 요청, 서버 에러 등 |

## authgate가 페이지를 제공하지 않는 것

| 페이지 | 이유 |
|--------|------|
| 로그인 화면 | IdP가 제공 (OAuth redirect) |
| 회원가입 폼 | 없음 (자동 가입) |
| 약관 동의 | 앱 책임 (각 앱이 자체 관리) |
| 프로필 편집 | 앱 책임 |
| 비밀번호 변경 | 없음 (IdP 위임) |
| 관리자 대시보드 | 없음 (DB 직접 관리) |

## 페이지별 상세

### 디바이스 코드 입력 페이지

```
┌──────────────────────────────────┐
│           authgate               │
│      Device Authorization        │
│                                  │
│  Enter the code displayed        │
│  in your terminal:               │
│                                  │
│  ┌────────────────────────────┐  │
│  │       ABCD-EFGH            │  │
│  └────────────────────────────┘  │
│                                  │
│  ┌────────────────────────────┐  │
│  │        Continue            │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
```

**URL**: `GET /device`
**입력**: `user_code` (text, uppercase, maxlength=9)
**성공 시**: → 디바이스 승인 페이지

### 디바이스 승인 페이지

```
┌──────────────────────────────────┐
│           authgate               │
│   Confirm Device Authorization   │
│                                  │
│  A CLI application is            │
│  requesting access with          │
│  this code:                      │
│                                  │
│  ┌────────────────────────────┐  │
│  │       B C D F - G H K M   │  │
│  └────────────────────────────┘  │
│                                  │
│  ┌────────────────────────────┐  │
│  │         Allow              │  │
│  └────────────────────────────┘  │
│  ┌────────────────────────────┐  │
│  │         Deny               │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
```

**전제 조건**: 유효한 세션 쿠키 필요. 없으면 IdP 로그인으로 redirect → `/device/auth/callback` 복귀 → `/device?user_code=XXXX` 재진입. `user_code`는 state 파라미터에 보존된다.
**입력**: `user_code` (hidden), `action` (approve/deny), `csrf_token` (hidden)
**보호 장치**: 승인/거부 POST는 CSRF double-submit cookie 방식으로 보호한다. 승인 페이지 렌더링 시 `csrf_token` 쿠키와 hidden input을 함께 발급하고, `/device/approve` 제출 시 둘이 일치해야 한다.
**성공 시**: 결과 페이지

### 결과 페이지

```
┌──────────────────────────────────┐
│           authgate               │
│                                  │
│            ✅ / ❌               │
│                                  │
│      Access Approved             │
│      (또는 Access Denied)        │
│                                  │
│  You have successfully           │
│  authorized the CLI application. │
│  You can close this window.      │
└──────────────────────────────────┘
```

## 디자인 원칙

1. **단순함** — CSS 인라인, 외부 의존성 없음
2. **브랜딩 최소** — authgate 로고 + 기능만
3. **반응형** — 모바일에서도 사용 가능
4. **접근성** — 시맨틱 HTML, label 연결, autofocus
5. **서버 제어 게이트 유지** — 디바이스 승인처럼 토큰 발급 전 게이트는 authgate 페이지에서 직접 처리
