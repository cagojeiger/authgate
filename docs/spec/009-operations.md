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

2. OIDC IdP 자격증명 발급
   → IdP(예: Google Cloud Console)에서 OAuth 2.0 Client ID/Secret 생성
   → **승인된 리디렉션 URI** (IdP에 등록하는 것):
     - `https://<authgate-domain>/login/callback` (브라우저 로그인용)
     - `https://<authgate-domain>/mcp/callback` (MCP 로그인용)
     - `https://<authgate-domain>/device/auth/callback` (Device 로그인용)
   → OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET 획득
     - Google 예시: OIDC_ISSUER_URL=https://accounts.google.com

   **주의: 이것은 upstream IdP redirect_uri다.**
   `oauth_clients` 테이블의 `redirect_uris`와 다른 것이다.
   - IdP redirect_uri = "IdP가 authgate로 돌려보내는 경로"
   - oauth_clients redirect_uri = "authgate가 각 앱으로 돌려보내는 경로"

3. 시크릿 생성
   → SESSION_SECRET: openssl rand -base64 32
   → signing_key.pem: authgate가 첫 실행 시 자동 생성 (또는 수동 생성)

4. 첫 번째 클라이언트 등록
   → clients.yaml 파일 생성 (아래 "클라이언트 등록" 참조)

5. 환경변수 설정 → 서버 시작
```

## 환경변수

| 변수 | 필수 | 기본값 | 설명 |
|------|------|--------|------|
| `PORT` | X | `8080` | 서버 포트 |
| `DATABASE_URL` | O | — | PostgreSQL 연결 문자열 |
| `SESSION_SECRET` | O | — | OIDC 암호화 키 (최소 32자) |
| `PUBLIC_URL` | O | — | 외부 접근 URL (예: `https://auth.example.com`) |
| `OIDC_ISSUER_URL` | X | `http://localhost:8082` | OIDC IdP issuer URL (예: `https://accounts.google.com`) |
| `OIDC_INTERNAL_URL` | X | — | 서버 간 OIDC 호출용 내부 URL (Docker/K8s 환경) |
| `OIDC_CLIENT_ID` | X | `authgate` | OIDC Client ID |
| `OIDC_CLIENT_SECRET` | O | — | OIDC Client Secret |
| `SESSION_TTL` | X | `86400` | 세션 수명 (초) |
| `ACCESS_TOKEN_TTL` | X | `900` | access_token 수명 (초, 15분) |
| `REFRESH_TOKEN_TTL` | X | `2592000` | refresh_token 수명 (초, 30일) |
| `DEV_MODE` | X | `false` | true 시: insecure 허용, cookie Secure=false |
| `CLIENT_CONFIG` | X | `/etc/authgate/clients.yaml` | 클라이언트 설정 YAML 파일 경로 (없으면 무시) |

### 프로덕션 필수 조건

`DEV_MODE=false` (기본값)일 때 다음이 강제됨:
- `SESSION_SECRET`이 비어있거나 32자 미만이면 **서버 시작 거부**
- `OIDC_ISSUER_URL`이 `https://`로 시작하지 않으면 **서버 시작 거부**
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

### YAML 파일 기반 (권장)

`clients.yaml` 파일로 클라이언트를 정의하면 authgate 시작 시 자동으로 DB에 upsert된다.

```yaml
# clients.yaml
clients:
  - client_id: my-web-app
    client_type: confidential
    client_secret_hash: "$2a$10$...bcrypt_hash..."
    login_channel: browser
    name: My Web App
    redirect_uris:
      - https://my-app.com/auth/callback
    allowed_scopes: [openid, profile, email]
    allowed_grant_types: [authorization_code, refresh_token]

  - client_id: my-cli
    client_type: public
    login_channel: browser
    name: My CLI Tool
    redirect_uris:
      - http://localhost:8080/callback
    allowed_scopes: [openid, profile, email, offline_access]
    allowed_grant_types: [authorization_code, "urn:ietf:params:oauth:grant-type:device_code", refresh_token]

  - client_id: my-mcp
    client_type: public
    login_channel: mcp
    name: My MCP Client
    redirect_uris:
      - http://localhost:3000/callback
    allowed_scopes: [openid, profile, email, offline_access]
    allowed_grant_types: [authorization_code, refresh_token]
```

MCP 클라이언트는 정적 YAML 등록 대신 [Spec 004](004-mcp-login.md)의 DCR(`POST /oauth/register`)을 사용할 수 있다.
운영 관점에서 YAML은 정적 클라이언트용, DCR은 동적 MCP 클라이언트용이다.
MCP는 원칙적으로 DCR 친화적인 채널로 본다.

배포 환경별 마운트:
- Docker Compose: `volumes: ["./clients.yaml:/etc/authgate/clients.yaml:ro"]`
- Kubernetes: ConfigMap → volumeMount
- 로컬 개발: `CLIENT_CONFIG=./clients.yaml`

**authgate 코드 변경 0줄.** YAML 파일만 수정하고 재시작하면 끝.

동작 규칙:
- YAML의 `client_id`가 DB에 없으면 INSERT
- 이미 있으면 UPDATE (redirect_uris, scopes 등 갱신)
- `client_secret_hash`를 생략하면 기존 DB 값 유지 (실수로 삭제 방지)
- YAML에 없는 기존 클라이언트는 그대로 유지 (삭제하지 않음)
- 파일이 없으면 경고 로그만 찍고 진행 (기존 DB 데이터 유지)

### SQL 직접 등록 (대안)

YAML 대신 SQL로 직접 등록할 수도 있다:

```sql
INSERT INTO oauth_clients (client_id, client_type, login_channel, name, redirect_uris, allowed_scopes, allowed_grant_types)
VALUES ('my-app', 'public', 'browser', 'My App', '{https://my-app.com/callback}', '{openid,profile,email}', '{authorization_code,refresh_token}');
```

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
| `GET /ready` | readiness (DB 연결 포함) | 200 `{"status":"ready"}` / 실패 시 503 `{"status":"not ready"}` |

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
