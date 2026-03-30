# Test 002: 채널 플로우 테스트

## 목적

Browser / Device / MCP / Refresh / Delete 각 채널이 공통 상태기계를 깨지 않고 동작하는지 검증한다.

## Browser

### Browser 가입 / 로그인

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `browser-001` | 미가입 | Browser 로그인 | Spec 001 가입 서브플로우 진입 | 가입은 Browser만 가능 |
| `browser-002` | 기존 `onboarding_complete` | Browser 로그인 | auto-approve + 토큰 발급 | 정상 로그인 |
| `browser-003` | `initial_onboarding_incomplete` | Browser 로그인 | terms 페이지 표시 | 온보딩 계속 |
| `browser-004` | `reconsent_required` | Browser 로그인 | terms 재동의 페이지 표시 | 버전 변경 처리 |
| `browser-005` | `recoverable_browser_only` | Browser 로그인 | active 복구 + 새 세션 | 삭제 유예 복구 |
| `browser-006` | `inactive` | Browser 로그인 | `account_inactive` | 차단 |
| `browser-007` | `recoverable_browser_only`, 복구 후 `CompleteAuthRequest` 실패 | Browser 재로그인 | 다음 재시도에서 정상 완료 | 복구 후 재시도 멱등성 |

### Browser 약관 제출

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `browser-terms-001` | `initial_onboarding_incomplete` | 체크박스 모두 선택 | `onboarding_complete` 전이 | 최초 가입 완료 |
| `browser-terms-002` | `reconsent_required` | 체크박스 모두 선택 | `onboarding_complete` 복귀 | 재동의 완료 |
| `browser-terms-003` | terms 미선택 | POST `/login/terms` | 200 + same page | 통과 불가 |
| `browser-terms-004` | age_confirm 미선택 | POST `/login/terms` | 200 + same page | 통과 불가 |

### Browser code → token 교환

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `browser-token-001` | `onboarding_complete` | POST `/oauth/token` (auth code) | 200 + 토큰 발급 | 정상 code exchange |
| `browser-token-002` | auth code 발급 후 `reconsent_required`로 변경 | POST `/oauth/token` | `invalid_grant` | 토큰 발급 시점 재검사 |
| `browser-token-003` | auth code 발급 후 `recoverable_browser_only` 또는 `inactive`로 변경 | POST `/oauth/token` | `invalid_grant` | 상태 변경 감지 |
| `browser-token-004` | 비정상 상태: auth code 발급 후 `initial_onboarding_incomplete` | POST `/oauth/token` | `invalid_grant` | impossible-state 방어 |

## Device

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `device-001` | `onboarding_complete` | `/oauth/device/authorize` → approve | 토큰 발급 성공 | 정상 Device 로그인 |
| `device-002` | 미가입 | `/device/auth/callback` | `signup_required` | Device에서 신규 가입 불가 |
| `device-003` | `initial_onboarding_incomplete` | `/device/auth/callback` | `signup_required` | callback 시점 차단 |
| `device-004` | `reconsent_required` | `/device/auth/callback` | `signup_required` | callback 시점 차단 |
| `device-005` | `recoverable_browser_only` | `/device/auth/callback` | `account_inactive` | Browser 복구만 가능 |
| `device-006` | `inactive` | `/device/auth/callback` | `account_inactive` | 차단 |
| `device-007` | approved state | 동시 polling 2회 | 정확히 1회만 성공 | consumed 원자성 |
| `device-008` | consumed state | 다시 polling | `invalid_grant` | 재사용 불가 |
| `device-009` | callback 시점 `onboarding_complete` | approve | 토큰 발급 성공 | approve 시점 재검사 통과 |
| `device-010` | callback 시점 `onboarding_complete`, approve 직전 `reconsent_required`로 변경 | approve | `signup_required` | approve 시점 상태 변경 감지 |
| `device-011` | callback 시점 `onboarding_complete`, approve 직전 `recoverable_browser_only` 또는 `inactive`로 변경 | approve | `account_inactive` | approve 시점 차단 |

## MCP

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `mcp-001` | `onboarding_complete` | `/oauth/authorize` → callback | 토큰 발급 성공 | 정상 MCP 로그인 |
| `mcp-002` | 미가입 | `/login/callback` | `signup_required` | MCP에서 신규 가입 불가 |
| `mcp-003` | `initial_onboarding_incomplete` | `/login/callback` | `signup_required` | MCP는 onboarding 채널이 아님 |
| `mcp-004` | `reconsent_required` | `/login/callback` | `signup_required` | MCP는 재동의 채널이 아님 |
| `mcp-005` | `recoverable_browser_only` | `/login/callback` | `account_inactive` | Browser 복구만 가능 |
| `mcp-006` | `inactive` | `/login/callback` | `account_inactive` | 차단 |
| `mcp-007` | PKCE 없음 | `/oauth/authorize` | `invalid_request` | PKCE 강제 |
| `mcp-token-001` | auth code 발급 후 `reconsent_required`로 변경 | POST `/oauth/token` | `invalid_grant` | MCP code exchange 재검사 |
| `mcp-token-002` | auth code 발급 후 `recoverable_browser_only` 또는 `inactive`로 변경 | POST `/oauth/token` | `invalid_grant` | MCP 토큰 발급 시점 차단 |
| `mcp-token-003` | 비정상 상태: auth code 발급 후 `initial_onboarding_incomplete` | POST `/oauth/token` | `invalid_grant` | impossible-state 방어 |

## Refresh

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `refresh-001` | `onboarding_complete` | valid refresh_token | 새 access/refresh 발급 | 정상 rotation |
| `refresh-002` | `initial_onboarding_incomplete` | valid refresh_token | `invalid_grant` | 미완료 차단 |
| `refresh-003` | `reconsent_required` | valid refresh_token | `invalid_grant` | 재동의 전 차단 |
| `refresh-004` | `recoverable_browser_only` | valid refresh_token | `invalid_grant` | 삭제 유예 차단 |
| `refresh-005` | `inactive` | valid refresh_token | `invalid_grant` | 비활성 차단 |
| `refresh-006` | same token concurrent 2회 | `/oauth/token` | 1회 성공 + 1회 실패 | row lock/원자성 |
| `refresh-007` | revoked token 재사용 | `/oauth/token` | family revoke + `invalid_grant` | 탈취 의심 처리 |

## Delete / Recover

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `account-001` | `onboarding_complete` | `DELETE /account` | `pending_deletion` | 상태 전이 |
| `account-002` | `pending_deletion` | `DELETE /account` | 200 멱등 | 재요청 무시 |
| `account-003` | `pending_deletion` | Browser 로그인 | active 복구 | 복구 경로 |
| `account-004` | `pending_deletion` | Device/MCP 로그인 | `account_inactive` | Browser만 복구 |
| `account-005` | `initial_onboarding_incomplete` | `DELETE /account` | `pending_deletion` | 미완료 계정도 삭제 요청 허용 |
| `account-006` | `reconsent_required` | `DELETE /account` | `pending_deletion` | 재동의 필요 상태도 삭제 허용 |
| `account-007` | `inactive` | `DELETE /account` | `account_inactive` 또는 차단 | 비활성 계정 삭제 차단 |

## 검증 포인트

```text
1. Browser만 onboarding을 계속할 수 있는가?
2. Device/MCP는 onboarding_complete 사용자만 통과하는가?
3. Refresh는 브라우저보다 더 엄격하게 차단되는가?
4. Delete/Recover가 상태기계를 깨지 않는가?
```
