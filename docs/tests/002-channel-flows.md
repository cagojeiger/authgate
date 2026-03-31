# Test 002: 채널 플로우 테스트

## 목적

Browser / Device / MCP / Refresh / Delete 각 채널이 공통 상태기계를 깨지 않고 동작하는지 검증한다.

## Browser

### Browser 가입 / 로그인

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `browser-001` | 미가입 | Browser 로그인 | Spec 001 가입 서브플로우 진입 | 가입은 Browser만 가능 |
| `browser-002` | 기존 `active` | Browser 로그인 | auto-approve + 토큰 발급 | 정상 로그인 |
| `browser-003` | `pending_deletion` | Browser 로그인 | active 복구 + 새 세션 | 삭제 유예 복구 |
| `browser-004` | `disabled` | Browser 로그인 | `account_inactive` | 차단 |
| `browser-004b` | `deleted` | Browser 로그인 | Spec 001 신규 가입 서브플로우 진입 | 재가입 경로 |
| `browser-005` | `pending_deletion`, 복구 후 auth_request 완료 상태 반영 실패 | Browser 재로그인 | 다음 재시도에서 정상 완료 | 복구 후 재시도 멱등성 |

### Browser code → token 교환

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `browser-token-001` | `active` | POST `/oauth/token` (auth code) | 200 + 토큰 발급 | 정상 code exchange |
| `browser-token-002` | auth code 발급 후 `pending_deletion` 또는 `disabled/deleted`로 변경 | POST `/oauth/token` | `invalid_grant` | 토큰 발급 시점 재검사 |

## Device

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `device-001` | `active` | `/oauth/device/authorize` → approve | 토큰 발급 성공 | 정상 Device 로그인 |
| `device-002` | 미가입 | `/device/auth/callback` | `account_not_found` | Device에서 신규 가입 불가 |
| `device-003` | `pending_deletion` | `/device/auth/callback` | `account_inactive` | Browser 복구만 가능 |
| `device-004` | `disabled` 또는 `deleted` | `/device/auth/callback` | `account_inactive` | 차단 |
| `device-005` | approved state | 동시 polling 2회 | 정확히 1회만 성공 | consumed 원자성 |
| `device-006` | consumed state | 다시 polling | `invalid_grant` | 재사용 불가 |
| `device-007` | callback 시점 `active` | approve | 토큰 발급 성공 | approve 시점 재검사 통과 |
| `device-008` | callback 시점 `active`, approve 직전 `pending_deletion` 또는 `disabled/deleted`로 변경 | approve | `account_inactive` | approve 시점 차단 |

## MCP

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `mcp-001` | `active` | `/authorize` → callback | 토큰 발급 성공 | 정상 MCP 로그인 |
| `mcp-002` | 미가입 | `/mcp/callback` | `account_not_found` | MCP에서 신규 가입 불가 |
| `mcp-003` | `pending_deletion` | `/mcp/callback` | `account_inactive` | Browser 복구만 가능 |
| `mcp-004` | `disabled` 또는 `deleted` | `/mcp/callback` | `account_inactive` | 차단 |
| `mcp-005` | auth code 발급 후 `code_verifier` 없이 토큰 교환 | `POST /oauth/token` | 토큰 발급 실패 | PKCE 강제 |
| `mcp-token-001` | auth code 발급 후 `pending_deletion` 또는 `disabled/deleted`로 변경 | POST `/oauth/token` | `invalid_grant` | MCP 토큰 발급 시점 차단 |

## Refresh

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `refresh-001` | `active` | valid refresh_token | 새 access/refresh 발급 | 정상 rotation |
| `refresh-002` | `pending_deletion` | valid refresh_token | `invalid_grant` | 삭제 유예 차단 |
| `refresh-003` | `disabled` 또는 `deleted` | valid refresh_token | `invalid_grant` | 비활성 차단 |
| `refresh-004` | same token concurrent 2회 | `/oauth/token` | 1회 성공 + 1회 실패 | row lock/원자성 |
| `refresh-005` | revoked token 재사용 | `/oauth/token` | family revoke + `invalid_grant` | 탈취 의심 처리 |

## Delete / Recover

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `account-001` | `active` | `DELETE /account` | `pending_deletion` | 상태 전이 |
| `account-002` | `pending_deletion` | `DELETE /account` | 200 멱등 | 재요청 무시 |
| `account-003` | `pending_deletion` | Browser 로그인 | active 복구 | 복구 경로 |
| `account-004` | `pending_deletion` | Device/MCP 로그인 | `account_inactive` | Browser만 복구 |
| `account-005` | `disabled` 또는 `deleted` | `DELETE /account` | `account_inactive` | 비활성 계정 삭제 차단 |

## 검증 포인트

```text
1. Browser만 pending_deletion을 복구할 수 있는가?
2. Device/MCP는 active 사용자만 통과하는가?
3. Refresh는 active 상태에서만 허용되는가?
4. Delete/Recover가 상태기계를 깨지 않는가?
```
