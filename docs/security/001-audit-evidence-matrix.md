# Security 001: Audit Evidence Matrix

검토일: 2026-05-15

## 목적

authgate 서버가 한국 개인정보보호법(PIPA), 통신 메타데이터 보존 요구,
SOC 2 준비 과정에서 증거로 제시할 수 있는 감사 이벤트와 운영 증거를
한 곳에 연결한다.

이 문서는 법률 의견서가 아니다. 보존기간, 정보주체 통지, 법적 예외,
소송 hold 같은 최종 판단은 운영/법무 정책에서 확정해야 한다. 여기서는
authgate 코드와 설정이 직접 생성하거나 검증할 수 있는 서버-side evidence만
다룬다.

## 증거 흐름

```text
HTTP request
  │
  ├─ clientinfo.Middleware
  │    └─ IP / User-Agent 추출
  │
  ├─ service layer
  │    └─ business event 결정
  │
  ├─ Storage.AuditLog
  │    ├─ event_type
  │    ├─ user_id
  │    ├─ ip_address
  │    ├─ user_agent
  │    ├─ metadata allowlist
  │    └─ best-effort INSERT
  │
  ▼
audit_log
  │
  ├─ append-only guard
  ├─ cleanup retention
  └─ PII anonymization after AUDIT_LOG_PII_RETENTION_DAYS
```

## 참조 기준

| 기준 | authgate에서의 해석 |
|------|------------------------|
| 개인정보 보호법 §29, §34 | 안전조치, 침해사고 조사, 통지 판단에 필요한 로그 근거 |
| 개인정보 보호법 시행령 §16 | 개인정보처리시스템 접속기록 보존기간의 하한선 |
| 통신비밀보호법 시행령 §41 | IP/접속시각 등 통신 메타데이터 보존기간 검토 기준 |
| SOC 2 Trust Services Criteria | CC6(접근통제), CC7(시스템 운영/탐지), CC8(변경관리) 증거 |
| ISMS-P 인증대상 기준 | 매출/이용자 임계 도달 시 별도 인증 범위 검토 기준 |

참고 URL:
- 개인정보 보호법: https://www.law.go.kr/LSW/lsInfoP.do?lsiSeq=248613
- 개인정보 보호법 시행령: https://www.law.go.kr/LSW/lsInfoP.do?lsId=011468
- 통신비밀보호법 시행령 §41: https://www.law.go.kr/LSW//lsLinkCommonInfo.do?lspttninfSeq=121362
- ISMS-P 인증대상: https://isms.kisa.or.kr/main/ispims/target/
- AICPA SOC: https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2

## 증거 수집 원칙

| 원칙 | authgate 적용 |
|------|---------------|
| 최소 수집 | audit metadata는 event별 allowlist만 저장 |
| 조사 가능성 | user_id, IP, User-Agent는 사고 조사 기간 동안 보존 |
| 보존 후 익명화 | `AUDIT_LOG_PII_RETENTION_DAYS` 이후 user_id/IP/User-Agent 제거 |
| 위변조 방지 | audit_log UPDATE/DELETE 제한 trigger |
| 실패 가시화 | audit write 실패는 metric으로 노출 |
| 변경관리 증거 | PR, CI, vulnerability check 결과를 SOC 2 evidence로 사용 |

## Control Matrix

| ID | 요구/질문 | authgate evidence | 코드/문서 위치 | 테스트 위치 | 상태 |
|----|-----------|-------------------|----------------|-------------|------|
| KR-PIPA-LOG-001 | 개인정보처리시스템 접근/행위 기록을 남기는가 | `audit_log`에 `user_id`, `event_type`, `ip_address`, `user_agent`, `created_at` 저장 | `internal/storage/audit.go`, `docs/spec/007-data-model.md` | `internal/service/audit_test.go`, `internal/storage/audit_test.go` | DONE |
| KR-PIPA-LOG-002 | 접속기록을 최소 1년 이상 보존하도록 설정할 수 있는가 | `AUDIT_LOG_PII_RETENTION_DAYS` 기본 1095일, 최소 365일 fail-fast | `internal/config/config.go`, `README.md` | `internal/config/config_test.go` | DONE |
| KR-PIPA-LOG-003 | 규모/민감정보 조건에서 2년 보존으로 올릴 수 있는가 | env로 730일 이상 설정 가능 | `internal/config/config.go` | `internal/config/config_test.go` | DONE |
| KR-PIPA-SEC-001 | 접속기록 위변조를 제한하는가 | audit_log append-only trigger, PII redaction 예외만 허용 | `migrations/003_audit_log_immutability.*.sql` | `internal/storage/audit_test.go` | DONE |
| KR-PIPA-SEC-002 | 불필요한 PII/secret이 audit metadata에 저장되지 않는가 | event별 metadata allowlist | `internal/storage/audit.go` | `internal/storage/audit_unit_test.go` | DONE |
| KR-PIPA-DEL-001 | 사용자 삭제/익명화 흐름을 추적할 수 있는가 | `auth.deletion_requested`, `auth.deletion_cancelled`, `auth.deletion_completed` | `internal/service/account.go`, `internal/service/login.go`, `internal/storage/cleanup_runner.go` | `internal/service/audit_test.go`, `internal/service/cleanup_test.go` | DONE |
| KR-PIPA-INC-001 | 침해 의심 이벤트를 조사할 수 있는가 | refresh token reuse와 family revoke 이벤트 | `internal/storage/storage_auth_tokens.go` | `internal/storage/audit_test.go` | DONE |
| KR-PIPA-INC-002 | audit log write 실패를 감지하는가 | `Storage.AuditLog` best-effort 실패 시 `slog.Error` 기록 | `internal/storage/audit.go`, `docs/spec/009-operations.md` | `internal/storage/audit_failure_unit_test.go` | DONE |
| KR-COMM-001 | IP/UA 등 접속 메타데이터를 추적할 수 있는가 | `audit_log.ip_address`, `audit_log.user_agent` | `internal/storage/audit.go`, `internal/clientinfo/*` | `internal/clientinfo/clientinfo_test.go` | DONE |
| SOC2-CC7-001 | 보안 이상징후를 탐지할 이벤트가 있는가 | inactive user access, refresh reuse detection, channel mismatch | `internal/service/*`, `internal/storage/storage_auth_tokens.go` | `internal/service/audit_test.go`, `internal/service/login_unit_test.go` | DONE |
| SOC2-CC7-002 | abuse 방어가 있는가 | per-IP rate limit for auth/token/callback endpoints, CIMD failure rate limit | `internal/app/routes.go`, `internal/middleware/ratelimit.go`, `internal/adapter/mcp/cimd.go` | `internal/integration/integration_ratelimit_test.go`, `internal/adapter/mcp/*ratelimit*_test.go` | DONE |
| SOC2-CC6-003 | 상위 IdP 로그인 CSRF/인가코드 인젝션을 방어하는가 | 상위 IdP 콜백에 암호화 state 쿠키 바인딩 + PKCE(S256) (browser/device/mcp 3채널) | `internal/upstream/oidc.go` (`rp.AuthURLHandler`/`CodeExchangeHandler`/`WithPKCE`) | `internal/upstream/oidc_test.go` | DONE |
| SOC2-CC8-001 | 변경관리 evidence를 확보할 수 있는가 | GitHub PR, CI checks, vulnerability check | GitHub repository / Actions | PR checks | DONE |
| SOC2-CC8-002 | dependency vulnerability evidence가 있는가 | `govulncheck` local/CI 실행 | GitHub Actions, PR body | CI `Vulnerability Check` | DONE |

## Event Coverage Matrix

| event_type | 트리거 | 주요 증거 | metadata allowlist | 구현 | 테스트 | 상태 |
|------------|--------|-----------|--------------------|------|--------|------|
| `auth.signup` | 신규 유저 가입 | user_id, IP, UA, created_at | `channel`, `client_id`, `client_name` | `internal/service/login.go` | `internal/service/audit_test.go` | DONE |
| `auth.login` | Browser/Device/MCP 로그인 성공 | user_id, IP, UA, created_at | `channel`, `session_id`, `client_id`, `client_name`, `reused_session`, `signup` | `internal/service/login.go`, `internal/service/device.go`, `internal/service/mcp_login.go` | `internal/service/audit_test.go` | DONE |
| `auth.channel_mismatch` | auth_request 채널 불일치 차단 | user_id, IP, UA, created_at | `expected_channel`, `actual_channel`, `client_id`, `client_name` | `internal/service/login.go` | `internal/service/login_unit_test.go` | DONE |
| `auth.inactive_user` | disabled/pending_deletion/deleted 접근 차단 | user_id, IP, UA, created_at | `status`, `channel`, `phase` | `internal/service/account.go`, `internal/service/login.go`, `internal/service/device.go`, `internal/service/mcp_login.go` | `internal/service/audit_test.go` | DONE |
| `auth.device_code_issued` | Device code 발급 | user_id(NULL), IP, UA, created_at | `client_id`, `client_name` | `internal/storage/storage_oidc_device.go` | `internal/storage/audit_test.go` | DONE |
| `auth.device_approved` | Device code 승인 | user_id, IP, UA, created_at | `client_id`, `client_name` | `internal/service/device.go` | `internal/service/audit_test.go` | DONE |
| `auth.device_denied` | Device code 거부 | user_id, IP, UA, created_at | `client_id`, `client_name` | `internal/service/device.go` | `internal/service/audit_test.go` | DONE |
| `auth.deletion_requested` | `DELETE /account` 성공 | user_id, IP, UA, created_at | `channel`, `session_id`, `client_id`, `client_name` | `internal/service/account.go` | `internal/service/audit_test.go` | DONE |
| `auth.deletion_cancelled` | pending_deletion 유저 브라우저 재로그인 복구 | user_id, IP, UA, created_at | `channel`, `session_id`, `client_id`, `client_name` | `internal/service/login.go` | `internal/service/audit_test.go` | DONE |
| `auth.deletion_completed` | cleanup PII scrub 완료 | user_id, created_at | `reason` | `internal/storage/cleanup_runner.go` | `internal/service/cleanup_test.go` | DONE |
| `auth.token_refreshed` | refresh token rotation 성공 | user_id, IP, UA, created_at | `client_id`, `client_name`, `family_id` | `internal/storage/storage_auth_tokens.go` | `internal/integration/integration_audit_test.go` | DONE |
| `auth.logout` | RP-Initiated Logout | user_id, IP, UA, created_at | `client_id`, `client_name` | `internal/storage/storage_auth_tokens.go` | `internal/storage/storage_integration_test.go` | DONE |
| `auth.token_revoked` | RFC 7009 revoke에서 refresh token 매칭 | user_id, IP, UA, created_at | `client_id`, `client_name` | `internal/storage/storage_auth_tokens.go` | `internal/integration/integration_audit_test.go` | DONE |
| `auth.refresh_reuse_detected` | 폐기 refresh token 재사용 | user_id, IP, UA, created_at | `family_id` | `internal/storage/storage_auth_tokens.go` | `internal/storage/audit_test.go` | DONE |
| `auth.refresh_family_revoked` | reuse 감지 후 family revoke | user_id, IP, UA, created_at | `family_id` | `internal/storage/storage_auth_tokens.go` | `internal/storage/audit_test.go` | DONE |

## Endpoint Coverage Matrix

| Endpoint | 민감도 | Audit evidence | Rate limit | 상태 |
|----------|--------|----------------|------------|------|
| `GET /login` | 인증 시작 | `auth.login` 재사용 세션, `auth.channel_mismatch`, `auth.deletion_cancelled` 일부 경로 | auth limiter | DONE |
| `GET /login/callback` | 인증 완료/가입 | `auth.signup`, `auth.login`, `auth.inactive_user` | auth limiter | DONE |
| `GET /mcp/login` | MCP 인증 시작 | `auth.inactive_user`, `auth.login` 일부 경로 | auth limiter | DONE |
| `GET /mcp/callback` | MCP 인증 완료 | `auth.login`, `auth.inactive_user` | auth limiter | DONE |
| `POST /oauth/token` | 토큰 발급/갱신 | `auth.token_refreshed`, reuse events | token limiter | DONE |
| `POST /oauth/revoke` | 토큰 폐기 | `auth.token_revoked` when matching refresh token | token limiter | DONE |
| `POST /oauth/introspect` | 토큰 상태 검증 | per-call audit 없음 (고빈도 token status check) | token limiter | GAP |
| `POST /oauth/device/authorize` | Device code 발급 | `auth.device_code_issued` | token limiter | DONE |
| `GET /device` | Device 코드 입력/승인 화면 | 없음 | auth limiter | DONE |
| `GET /device/auth/callback` | Device 로그인 완료 | `auth.login`, `auth.inactive_user` | auth limiter | DONE |
| `POST /device/approve` | Device 승인/거부 | `auth.device_approved`, `auth.device_denied`, `auth.inactive_user` | token limiter | DONE |
| `DELETE /account` | 계정 삭제 요청 | `auth.deletion_requested`, inactive user block | auth limiter | DONE |

## 남은 GAP

| GAP | 설명 | 다음 작업 후보 |
|-----|------|----------------|
| GAP-OPS-001 | SOC 2 운영 evidence(PR 리뷰, access review, backup restore test)는 GitHub/운영 시스템에 존재해야 하며 authgate DB에는 저장하지 않는다. | 운영 evidence export/checklist 문서 |
| GAP-SEC-001 | 상위 IdP id_token의 `nonce` 검증 미적용. state 쿠키 + PKCE로 로그인 CSRF는 차단했으나 id_token 재생 바인딩은 별도. | `rp.WithVerifierOpts(rp.WithNonce(...))` + 요청별 nonce 저장 후속 PR |

## 완료 기준

이 문서의 `DONE` 항목은 다음 조건을 만족해야 한다.

```text
1. event_type 또는 운영 evidence 이름이 고정되어 있다.
2. 구현 위치가 명확하다.
3. 테스트 위치가 명확하다.
4. metadata에 저장하는 값이 최소화되어 있다.
5. 실패 시 silent하게 깨지는 통제는 metric 또는 CI로 감지된다.
```

새 보안 이벤트를 추가할 때는 이 문서와
[`docs/tests/004-audit-events.md`](../tests/004-audit-events.md)를 함께 갱신한다.
