# Spec 009: 운영

## 개요

authgate의 초기 설정, 시크릿 관리, 키 로테이션, 일상 운영에 대한 스펙.
운영자는 authgate에 로그인하지 않는다. 환경변수, DB, 키 파일로 관리한다.

## 초기 설정

authgate를 처음 배포할 때 필요한 것:

```
1. PostgreSQL 준비
   → DB 생성 (authgate)
   → 마이그레이션 실행 (001_init.sql)

2. Google OAuth 자격증명 발급
   → Google Cloud Console에서 OAuth 2.0 Client ID 생성
   → **승인된 리디렉션 URI** (Google에 등록하는 것):
     - `https://<authgate-domain>/login/callback` (브라우저/MCP 로그인용)
     - `https://<authgate-domain>/device/auth/callback` (Device 로그인용)
   → GOOGLE_CLIENT_ID, GOOGLE_SECRET 획득

   **주의: 이것은 Google upstream redirect_uri다.**
   `oauth_clients` 테이블의 `redirect_uris`와 다른 것이다.
   - Google redirect_uri = "Google이 authgate로 돌려보내는 경로"
   - oauth_clients redirect_uri = "authgate가 각 앱으로 돌려보내는 경로"

3. 시크릿 생성
   → SESSION_SECRET: openssl rand -base64 32
   → signing_key.pem: authgate가 첫 실행 시 자동 생성 (또는 수동 생성)

4. 첫 번째 클라이언트 등록
   → DB에 INSERT (아래 "클라이언트 등록" 참조)

5. 환경변수 설정 → 서버 시작
```

## 환경변수

| 변수 | 필수 | 기본값 | 설명 |
|------|------|--------|------|
| `PORT` | X | `8080` | 서버 포트 |
| `DATABASE_URL` | O | — | PostgreSQL 연결 문자열 |
| `SESSION_SECRET` | O | — | OIDC 암호화 키 (최소 32자) |
| `PUBLIC_URL` | O | — | 외부 접근 URL (예: `https://auth.example.com`) |
| `UPSTREAM_PROVIDER` | X | `mock` | IdP 선택 (`google` / `mock`) |
| `GOOGLE_CLIENT_ID` | △ | — | Google OAuth Client ID (google일 때 필수) |
| `GOOGLE_SECRET` | △ | — | Google OAuth Secret (google일 때 필수) |
| `MOCK_IDP_URL` | X | `http://localhost:8082` | Mock IdP URL (개발용) |
| `MOCK_IDP_PUBLIC_URL` | X | `http://localhost:8082` | Mock IdP 외부 URL |
| `SESSION_TTL` | X | `86400` | 세션 수명 (초) |
| `ACCESS_TOKEN_TTL` | X | `900` | access_token 수명 (초, 15분) |
| `REFRESH_TOKEN_TTL` | X | `2592000` | refresh_token 수명 (초, 30일) |
| `TERMS_VERSION` | X | `2026-03-28` | 현재 약관 버전 (변경 시 재동의) |
| `PRIVACY_VERSION` | X | `2026-03-28` | 현재 개인정보 처리방침 버전 |
| `DEV_MODE` | X | `false` | true 시: insecure 허용, mock provider 허용, cookie Secure=false |

### 프로덕션 필수 조건

`DEV_MODE=false` (기본값)일 때 다음이 강제됨:
- `SESSION_SECRET`이 기본값이면 **서버 시작 거부**
- `UPSTREAM_PROVIDER`가 `google`이 아니면 **서버 시작 거부**
- 쿠키 `Secure=true`
- `op.WithAllowInsecure()` 비활성

## 시크릿 관리

### SESSION_SECRET

```bash
# 생성
openssl rand -base64 32

# 용도: OIDC 프로바이더의 CryptoKey (state 암호화, CSRF 보호)
# 교체: 변경 시 진행 중인 로그인 플로우 실패 (auth_requests 무효화)
# 권장: 배포 후 변경하지 않음. 변경 필요 시 트래픽 낮은 시간에
```

### signing_key.pem (RSA 서명 키)

```bash
# 자동 생성: authgate 첫 실행 시 signing_key.pem 파일 생성 (2048-bit RSA)
# 수동 생성:
openssl genrsa -out signing_key.pem 2048
chmod 600 signing_key.pem

# 용도: JWT (access_token, id_token) 서명
# 교체: 아래 "키 로테이션" 참조
```

### client_secret (각 앱별)

```bash
# 생성
SECRET=$(openssl rand -base64 32)
HASH=$(htpasswd -nbBC 10 "" "$SECRET" | cut -d: -f2)

# DB 등록 시 해시만 저장
INSERT INTO oauth_clients (client_id, client_secret_hash, ...)
VALUES ('my-app', '$2a$10$...hashed...', ...);

# 앱에게 평문 전달 (1회만, 이후 조회 불가)
```

## 키 로테이션

### 왜 필요한가

signing_key를 교체하면 기존 JWT의 서명을 검증할 수 없다.
**키 2개를 겹쳐 운영**해야 무중단 교체가 가능하다.

### 로테이션 절차

```
교체 전:
  JWKS = [key-1 (signing)]
  새 JWT → key-1으로 서명
  앱 → key-1으로 검증

Step 1: 새 키 추가 (기존 유지)
  JWKS = [key-2 (signing), key-1 (verify only)]
  새 JWT → key-2로 서명
  기존 JWT → key-1으로 검증 가능

Step 2: 겹치는 기간 대기 (최소 ACCESS_TOKEN_TTL = 15분)
  앱이 JWKS 캐시 갱신 → key-2 인식
  key-1 JWT는 만료되어 감

Step 3: 구 키 제거
  JWKS = [key-2 (signing)]
  key-1 JWT는 이미 전부 만료
```

### 구현 요구사항

```
signing key 저장:
  - 현재: 단일 파일 (signing_key.pem)
  - 필요: 2개 슬롯 (current + previous)

JWKS 엔드포인트:
  - 항상 유효한 키 전부 반환 (kid로 구분)
  - 앱은 JWT의 kid와 JWKS의 kid를 매칭하여 검증

앱 측 요구사항:
  - JWKS 캐시 + kid miss 시 재fetch
  - 추가 작업 불필요 (kid 매칭은 JWT 표준 동작)
```

### 로테이션 명령 (향후)

```bash
# 현재: 수동 (파일 교체 + 서버 재시작)
# 향후: CLI 명령 또는 API
authgate key rotate        # 새 키 생성 + 구 키 보존
authgate key list          # 현재 키 목록
authgate key remove <kid>  # 구 키 제거
```

## 클라이언트 등록

새 앱을 authgate에 연결할 때:

```sql
-- confidential client (백엔드 앱, client_secret 있음)
INSERT INTO oauth_clients (
  client_id, client_secret_hash, client_type, name,
  redirect_uris, allowed_scopes, allowed_grant_types
) VALUES (
  'my-web-app',
  '$2a$10$...bcrypt_hash...',
  'confidential',
  'My Web App',
  ARRAY['https://my-app.com/auth/callback'],
  ARRAY['openid', 'profile', 'email'],
  ARRAY['authorization_code', 'refresh_token']
);

-- public client (SPA/CLI/MCP/브라우저 SPA, client_secret 없음)
-- 브라우저 웹 앱도 SPA라면 public client로 등록 가능 (Spec 002 참조)
INSERT INTO oauth_clients (
  client_id, client_secret_hash, client_type, name,
  redirect_uris, allowed_scopes, allowed_grant_types
) VALUES (
  'my-cli',
  NULL,
  'public',
  'My CLI Tool',
  ARRAY['http://localhost:8080/callback'],
  ARRAY['openid', 'profile', 'email'],
  ARRAY['device_code', 'refresh_token']
);
```

**authgate 코드 변경 0줄.** DB에 INSERT하면 끝.

### 클라이언트 삭제

`auth_requests.client_id`, `device_codes.client_id`, `refresh_tokens.client_id`는
`oauth_clients.client_id`를 논리 참조한다. FK는 없으므로 삭제 전 운영 절차로 정합성을 보장한다.

```sql
-- 1. 진행 중 auth_request 확인 (없어야 함)
SELECT COUNT(*) FROM auth_requests WHERE client_id = 'my-cli' AND expires_at > NOW();

-- 2. 진행 중 device_code 확인 (없어야 함)
SELECT COUNT(*) FROM device_codes
WHERE client_id = 'my-cli'
  AND expires_at > NOW()
  AND state IN ('pending', 'approved');

-- 3. 남은 refresh_token 전부 revoke
UPDATE refresh_tokens
SET revoked_at = NOW()
WHERE client_id = 'my-cli'
  AND revoked_at IS NULL;

-- 4. 확인 후 클라이언트 삭제
DELETE FROM oauth_clients WHERE client_id = 'my-cli';
```

운영 규칙:
- auth_requests/device_codes가 살아 있으면 클라이언트를 삭제하지 않는다.
- refresh_tokens는 삭제 전 전부 revoke한다.
- 실제 hard delete는 Spec 005 token cleanup 절차에 맡긴다.

## 일상 운영

### 유저 정지

```sql
UPDATE users SET status = 'disabled', updated_at = NOW() WHERE email = 'bad@example.com';
-- 즉시 로그인/토큰 갱신 차단
-- 복구: UPDATE users SET status = 'active', updated_at = NOW() WHERE email = '...';
```

### 약관 버전 변경

```bash
# 환경변수 변경 후 재배포
TERMS_VERSION=2027-01-01
PRIVACY_VERSION=2027-01-01
# → 모든 기존 유저가 다음 로그인 시 재동의 필요
```

### audit_log 조회

```sql
-- 최근 로그인 이벤트
SELECT * FROM audit_log WHERE event_type = 'auth.login' ORDER BY created_at DESC LIMIT 50;

-- 특정 유저 이력
SELECT * FROM audit_log WHERE user_id = 'uuid-...' ORDER BY created_at DESC;

-- 의심스러운 이벤트
SELECT * FROM audit_log WHERE event_type = 'auth.inactive_user' ORDER BY created_at DESC;
```

## 모니터링

| 엔드포인트 | 용도 | 정상 응답 |
|-----------|------|----------|
| `GET /health` | liveness (프로세스 살아있나) | 200 `{"status":"healthy"}` |
| `GET /ready` | readiness (DB 연결 포함) | 200 `{"status":"ready"}` |

### 감시해야 할 것

| 항목 | 방법 | 위험 신호 |
|------|------|----------|
| DB 연결 | `/ready` 주기적 체크 | 503 반환 |
| cleanup 고루틴 | audit_log에 `auth.deletion_completed` 확인 | 30일+ pending_deletion 유저 존재 |
| signing_key | JWKS 엔드포인트 체크 | 키 0개 반환 |
| 디스크 | signing_key.pem 파일 존재 확인 | 파일 없음 → 재시작마다 키 변경 |

## 백업/복구

| 대상 | 백업 방법 | 복구 |
|------|----------|------|
| PostgreSQL | `pg_dump` 정기 백업 | `pg_restore` |
| signing_key.pem | 파일 복사 (암호화 보관) | 파일 복원 → 재시작 |
| 환경변수 | `.env` 또는 시크릿 매니저 | 재설정 |

**signing_key.pem을 잃으면 모든 기존 JWT가 무효화됩니다.** 반드시 백업.
