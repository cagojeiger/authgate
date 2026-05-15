# Test 004: 감사 이벤트 테스트

## 목적

`audit_log.event_type`와 `metadata`가 스펙에 맞게 기록되는지 검증한다.
상태 전이 자체뿐 아니라, 운영/보안 관측성이 보장되는지를 확인한다.

## 검증 대상

참조 스펙:
- [Spec 007 데이터 모델](../spec/007-data-model.md)
- [Spec 003 Device 로그인](../spec/003-device-login.md)
- [Spec 005 토큰 Lifecycle](../spec/005-token-lifecycle.md)
- [Spec 006 계정 Lifecycle](../spec/006-account-lifecycle.md)

## 이벤트 테스트 리스트

| ID | 시나리오 | 기대 이벤트 | 검증 포인트 |
|----|----------|------------|-------------|
| `audit-001` | Browser 신규 가입 | `auth.signup` | 계정 생성 직후 1회 기록, `metadata.channel`=`browser` + `metadata.client_id` + `metadata.client_name` 포함 (#204) |
| `audit-002` | Browser/MCP/Device 로그인 성공 | `auth.login` | `metadata.channel`이 `browser/device/mcp` 중 하나로 기록 |
| `audit-003` | Device 승인 | `auth.device_approved` | 승인 시 1회 기록, `metadata.client_id` + `metadata.client_name` 포함 (#205) |
| `audit-004` | Device 거부 | `auth.device_denied` | 거부 시 1회 기록, `metadata.client_id` + `metadata.client_name` 포함 (#205) |
| `audit-005` | DELETE /account | `auth.deletion_requested` | 삭제 요청 시 즉시 기록 |
| `audit-006` | pending_deletion Browser 복구 | `auth.deletion_cancelled` | 자동 복구 시 기록 |
| `audit-007` | deletion cleanup 완료 | `auth.deletion_completed` | PII 스크러빙 완료 시 기록 |
| `audit-008` | pending_deletion/disabled/deleted 로그인 시도 | `auth.inactive_user` | `metadata.status` 포함 |
| `audit-009` | refresh token 재사용 탐지 | `auth.refresh_reuse_detected` | `metadata.family_id` 기록 |
| `audit-010` | family 전체 revoke | `auth.refresh_family_revoked` | `metadata.family_id` 기록 |
| `audit-011` | client 컨텍스트가 있는 모든 이벤트 | (해당 이벤트) | `metadata.client_id` + `metadata.client_name`이 함께 기록 (#147) |
| `audit-012` | OIDC RP-Initiated Logout (`/end_session`) 호출 | `auth.logout` | **세션 폐기**만 의미. 발급된 refresh 토큰은 자연 만료/명시적 revoke 전까지 유효. `metadata.client_id` + `client_name` 함께 기록 (#191, [Spec 005 Logout vs. Revoke](../spec/005-token-lifecycle.md#logout-vs-revoke-191)) |
| `audit-013` | RFC 7009 `/oauth/revoke` 호출에서 **매칭되는 refresh token이 발견되어 revoke된 경우** | `auth.token_revoked` | `metadata.client_id` 기록. 알려지지 않은 토큰은 RFC 7009 §2.2에 따라 200 OK만 반환하고 이벤트는 발생하지 않음. `auth.logout`과 별개 이벤트 (#191) |
| `audit-014` | audit metadata 저장 | (해당 이벤트) | 이벤트별 allowlist에 없는 key는 저장하지 않음. 예: `email`, token, secret류 임의 key는 drop |
| `audit-015` | Console client/connection/session 조회 | `console.clients_listed`, `console.connections_listed`, `console.sessions_listed` | 성공 응답 후 `metadata.result_count` 기록. 응답의 IP/UA/세션 상세 자체는 metadata에 넣지 않음 |
| `audit-016` | Console audit log 조회 | `console.audit_log_viewed` | 성공 응답 후 `metadata.page`, `metadata.limit`, `metadata.result_count` 기록 |
| `audit-017` | Console 401/403 접근 거부 | `console.access_denied` | 401은 `user_id=NULL`, 403은 식별된 `user_id` + `metadata.user_status` 기록. `metadata.operation`, `status_code`, `reason` 포함 |
| `audit-018` | Device code 발급 | `auth.device_code_issued` | 승인 전 단계라 `user_id=NULL`. `metadata.client_id` + `metadata.client_name`만 기록하고 `device_code`/`user_code`는 저장하지 않음 |

## 채널별 auth.login 검증

| ID | 채널 | 입력 | 기대 metadata |
|----|------|------|---------------|
| `audit-login-001` | browser | Browser 로그인 성공 | `{channel: "browser", client_id, client_name}` |
| `audit-login-002` | device | Device 로그인 성공 | `{channel: "device", client_id, client_name}` |
| `audit-login-003` | mcp | MCP 로그인 성공 (신규 callback 및 활성 세션 자동 승인 모두) | 공통 `{channel: "mcp", session_id, client_id, client_name}`; 세션 재사용 경로는 추가로 `reused_session: true` 포함 (#206, 브라우저 #131 mirror) |

## 보안 이벤트 검증

| ID | 시나리오 | 기대 결과 | 검증 포인트 |
|----|----------|----------|-------------|
| `audit-security-001` | 폐기된 refresh_token 제출 | `auth.refresh_reuse_detected` | 탈취 의심 이벤트 발생 |
| `audit-security-002` | family revoke 수행 | `auth.refresh_family_revoked` | 영향 범위 추적 가능 |
| `audit-security-003` | pending_deletion/disabled/deleted 로그인 시도 | `auth.inactive_user` | status 포함 |

## 검증 포인트

```text
1. 상태 전이뿐 아니라 중요한 운영 이벤트가 빠짐없이 기록되는가?
2. channel metadata가 browser/device/mcp로 일관되게 기록되는가?
3. 보안 사고 대응용 family_id, status 같은 핵심 metadata가 남는가?
4. success/failure 이벤트가 중복 기록되거나 누락되지 않는가?
5. 이벤트별 metadata allowlist가 PII/secret류 임의 key 저장을 차단하는가?
```
