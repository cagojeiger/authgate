# Security 003: Endpoint Coverage

검토일: 2026-05-15

## 목적

authgate가 노출하는 각 HTTP endpoint의 audit/rate-limit 커버리지를 추적한다.
endpoint가 새로 생기거나 사라질 때 audit/rate limit 누락이 발생하지 않도록 한다.

## 독자

보안 리뷰어, 신규 endpoint를 추가하는 개발자.

## 갱신 시점

- 새 endpoint가 추가됐을 때
- endpoint의 rate limit 분류(token/auth)가 바뀌었을 때
- endpoint에서 발생하는 audit event가 추가/제거됐을 때

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
| `GET /console/clients` | 연결 앱 조회 | `console.clients_listed` | auth limiter | DONE |
| `GET /console/me/connections` | 연결/권한 조회 | `console.connections_listed` | auth limiter | DONE |
| `DELETE /console/me/connections/{client_id}` | 연결 폐기 | `auth.connection_revoked` | auth limiter | DONE |
| `GET /console/me/sessions` | 세션/IP/UA 조회 | `console.sessions_listed` | auth limiter | DONE |
| `DELETE /console/me/sessions/{id}` | 세션 폐기 | `auth.session_revoked` | auth limiter | DONE |
| `POST /console/me/sessions/revoke-others` | 세션 일괄 폐기 | `auth.other_sessions_revoked` | auth limiter | DONE |
| `GET /console/me/audit-log` | 감사 로그 조회 | `console.audit_log_viewed` | auth limiter | DONE |

## 새 endpoint 추가 시

새 endpoint가 생기면 이 표에 행을 추가하고, rate limit 분류(token/auth)와 발생 가능한 audit event를 명시한다.
새 audit event가 함께 생기면 [`002-event-catalog.md`](002-event-catalog.md)도 갱신한다.
control evidence를 새로 제공한다면 [`001-control-evidence.md`](001-control-evidence.md)도 갱신한다.
