# Spec 008: authgate 페이지

## 개요

authgate가 직접 제공하는 HTML 페이지 목록.
이 페이지들은 토큰 발급 전 조건(약관 동의, 디바이스 승인)을 처리하므로 authgate 책임이다.
앱이 이 페이지를 직접 구현하면 약관 우회 경로가 생기므로, authgate가 중앙에서 관리한다.

## 페이지 목록

| 페이지 | URL | 용도 | 언제 표시되나 |
|--------|-----|------|-------------|
| 약관 동의 | `/login/terms` (GET: 표시, POST: 제출) | 이용약관 + 개인정보 동의 + 연령 확인 | 신규 가입 시, 약관 버전 변경 시 |
| 디바이스 코드 입력 | `/device` (GET) | user_code 입력 폼 | CLI 로그인 시 사용자가 브라우저에서 접근 |
| 디바이스 승인 | `/device?user_code=XXXX` (GET) | 승인/거부 선택 | user_code 입력 후 |
| 결과 | `/device/approve` (POST 결과) | 승인/거부 결과 표시 | 디바이스 승인/거부 후 |

## authgate가 페이지를 제공하지 않는 것

| 페이지 | 이유 |
|--------|------|
| 로그인 화면 | Google이 제공 (OAuth redirect) |
| 회원가입 폼 | 없음 (자동 가입) |
| 프로필 편집 | 앱 책임 |
| 비밀번호 변경 | 없음 (Google-only) |
| 관리자 대시보드 | 없음 (DB 직접 관리) |

## 페이지별 상세

### 약관 동의 페이지

```
┌──────────────────────────────────┐
│           authgate               │
│         Almost there             │
│                                  │
│  To continue, please review      │
│  and accept our terms:           │
│                                  │
│  ☐ I agree to the Terms of      │
│    Service and Privacy Policy    │
│                                  │
│  ☐ I confirm that I am 13       │
│    years or older                │
│                                  │
│  ┌────────────────────────────┐  │
│  │        Continue            │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
```

**표시 조건**: 가입 온보딩 미완료 (`terms_accepted_at IS NULL` OR `privacy_accepted_at IS NULL` OR 버전 불일치)
**입력**: `authRequestID` (hidden), `terms_agree` (checkbox), `privacy_agree` (checkbox), `age_confirm` (checkbox)
**성공 시**: `AcceptTerms(terms_version, privacy_version)` → `autoApprove` → 토큰 발급
**실패 시**: 체크박스 미선택 → 200 + 같은 페이지 재표시 (에러 메시지 포함)

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

**전제 조건**: 유효한 세션 쿠키 필요 (없으면 로그인 페이지로 redirect, user_code 보존하여 로그인 후 복귀)
**입력**: `user_code` (hidden), `action` (approve/deny)
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
