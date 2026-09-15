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
| `audit-001b` | 클라이언트 `access` 정책이 가입·로그인·세션 재사용·device 콜백·승인·code 교환·device polling·refresh 거부 | `auth.access_denied` | 거부 1회당 1행. `metadata.client_id`, `client_name`, `channel`(`browser/mcp/device/refresh`; code 교환은 클라이언트의 로그인 채널, device polling은 `device`), `reason`(`deny_listed/not_allowed/email_unverified`), `domain`(이메일 도메인만, 주소 없음), `signup`. 가입 거부면 `user_id` null. 비활성 계정·채널 불일치는 이 이벤트 대신 기존 이벤트만 |
| `audit-002` | Browser/MCP/Device 로그인 성공 | `auth.login` | `metadata.channel`이 `browser/device/mcp` 중 하나로 기록 |
| `audit-003` | Device 승인 | `auth.device_approved` | 승인 시 1회 기록, `metadata.client_id` + `metadata.client_name` 포함 (#205) |
| `audit-004` | Device 거부 | `auth.device_denied` | 거부 시 1회 기록, `metadata.client_id` + `metadata.client_name` 포함 (#205) |
| `audit-006` | pending_deletion Browser 복구 | `auth.deletion_cancelled` | 자동 복구 시 기록. `metadata.channel`, `session_id`, `client_id`, `client_name` 포함 (#211) |
| `audit-007` | deletion cleanup 완료 | `auth.deletion_completed` | PII 스크러빙 완료 시 기록. `metadata.reason=pending_deletion_expired` 포함 (#211) |
| `audit-008` | pending_deletion/disabled/deleted 로그인 시도 | `auth.inactive_user` | `metadata.status` 포함 |
| `audit-009` | refresh token 재사용 탐지 | `auth.refresh_reuse_detected` | `metadata.family_id` 기록 |
| `audit-010` | family 전체 revoke | `auth.refresh_family_revoked` | `metadata.family_id` 기록 |
| `audit-010c` | 교환된 토큰을 유예 안에 재제출 / 상한 초과 | `auth.refresh_reuse_grace` | 발급 시 `outcome=issued` 1행, 상한 거부 시 `outcome=refused` 1행, `metadata.family_id` 기록 |
| `audit-010b` | 이미 revoke된 family의 토큰을 다른 IP에서 반복 제출 | `auth.refresh_reuse_detected`, `auth.refresh_family_revoked` | reuse는 제출마다 1행(뒤 제출자 IP 포함), family revoke는 1행, 모든 제출 `invalid_grant`, 살아있는 토큰 0 |
| `audit-011` | client 컨텍스트가 있는 모든 이벤트 | (해당 이벤트) | `metadata.client_id` + `metadata.client_name`이 함께 기록 (#147) |
| `audit-012` | OIDC RP-Initiated Logout (`/end_session`)으로 세션 종료 | `auth.logout` | 실제로 세션을 폐기했을 때만 1행(`RevokeSessionsByUserID` 영향 행 > 0). 종료할 세션이 없거나, 확인 페이지만 렌더링·CSRF 거부된 요청, 이미 끝난 세션에 대한 반복 요청은 기록 없음 (`logout-001`~`logout-014`). **세션 폐기**만 의미. 발급된 refresh 토큰은 자연 만료/명시적 revoke 전까지 유효. `metadata.client_id` + `client_name` 함께 기록 (#191, [Spec 005 Logout vs. Revoke](../spec/005-token-lifecycle.md#logout-vs-revoke-191)) |
| `audit-013` | RFC 7009 `/oauth/revoke` 호출에서 **매칭되는 refresh token이 발견되어 그 grant의 살아있는 토큰이 revoke된 경우** | `auth.token_revoked` | `metadata.client_id` 기록. 알려지지 않은 토큰은 RFC 7009 §2.2에 따라 200 OK만 반환하고 이벤트는 발생하지 않음. `auth.logout`과 별개 이벤트 (#191) |
| `audit-014` | audit metadata 저장 | (해당 이벤트) | 이벤트별 allowlist에 없는 key는 저장하지 않음. 예: `email`, token, secret류 임의 key는 drop |
| `audit-015` | Device code 발급 | `auth.device_code_issued` | 승인 전 단계라 `user_id=NULL`. `metadata.client_id` + `metadata.client_name`만 기록하고 `device_code`/`user_code`는 저장하지 않음 |
| `audit-016` | refresh token rotation 성공 | **기록 없음** | 성공한 갱신은 감사 대상이 아니다. `refresh_tokens.used_at` 이 마지막 사용 시각을 보유 |

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
