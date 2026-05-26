# Security 002: Event Catalog

검토일: 2026-05-15

## 목적

authgate가 발급하는 audit event 카탈로그. 각 `event_type`이 언제 트리거되고,
어떤 metadata를 저장하며, 어느 코드에서 발생하는지 명시한다.

## 독자

개발자, SRE. 새 audit event를 추가하거나 기존 event의 metadata를 바꿀 때 본다.

## 갱신 시점

- 새 `event_type`이 추가/변경됐을 때
- metadata allowlist가 바뀌었을 때
- 트리거 위치(코드 경로)가 이동했을 때

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
| `auth.connection_revoked` | console connection revoke | user_id, IP, UA, created_at | `client_id`, `client_name` | `internal/service/console.go` | `internal/service/console_unit_test.go` | DONE |
| `auth.session_revoked` | console session revoke | user_id, IP, UA, created_at | `session_id` | `internal/service/console.go` | `internal/service/console_unit_test.go` | DONE |
| `auth.other_sessions_revoked` | current session 외 revoke | user_id, IP, UA, created_at | `current_session_id` | `internal/service/console.go` | `internal/service/console_unit_test.go` | DONE |
| `console.clients_listed` | `/console/clients` 성공 조회 | user_id, IP, UA, created_at | `result_count` | `internal/service/console.go` | `internal/service/console_unit_test.go` | DONE |
| `console.connections_listed` | `/console/me/connections` 성공 조회 | user_id, IP, UA, created_at | `result_count` | `internal/service/console.go` | `internal/service/console_unit_test.go` | DONE |
| `console.sessions_listed` | `/console/me/sessions` 성공 조회 | user_id, IP, UA, created_at | `result_count` | `internal/service/console.go` | `internal/service/console_unit_test.go` | DONE |
| `console.audit_log_viewed` | `/console/me/audit-log` 성공 조회 | user_id, IP, UA, created_at | `page`, `limit`, `result_count` | `internal/service/console.go` | `internal/service/console_unit_test.go` | DONE |
| `console.access_denied` | Console 401/403 접근 거부 | user_id(403만), IP, UA, created_at | `operation`, `status_code`, `reason`, `user_status` | `internal/service/console.go` | `internal/service/console_unit_test.go` | DONE |

## 새 이벤트 추가 시

이 파일과 [`docs/tests/004-audit-events.md`](../tests/004-audit-events.md)를 함께 갱신한다.
새 이벤트가 특정 control evidence를 새로 제공한다면 [`001-control-evidence.md`](001-control-evidence.md)도 갱신한다.
endpoint와 1:1로 매핑되는 이벤트라면 [`003-endpoint-coverage.md`](003-endpoint-coverage.md)도 함께 갱신한다.
