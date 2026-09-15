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
| `device-samesite` | 세션 없음 | `/device/auth/callback` | 302 `/device?user_code=…` + 세션 쿠키 `SameSite=Lax` | IdP 복귀 리다이렉트에서 쿠키 생존 ([Spec 003](../spec/003-device-login.md#세션-없이-승인-시-흐름)) |
| `device-samesite-2` | 유효 세션 | `/device?user_code=…` | 승인 화면 + `csrf_token` `SameSite=Strict` | 세션만 완화하고 CSRF는 조이는 조합 유지 |

## MCP

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `mcp-001` | `active` | `/authorize` → callback | 토큰 발급 성공 | 정상 MCP 로그인 |
| `mcp-002` | 미가입 | `/mcp/callback` | `account_not_found` | MCP에서 신규 가입 불가 |
| `mcp-003` | `pending_deletion` | `/mcp/callback` | `account_inactive` | Browser 복구만 가능 |
| `mcp-004` | `disabled` 또는 `deleted` | `/mcp/callback` | `account_inactive` | 차단 |
| `mcp-005` | auth code 발급 후 `code_verifier` 없이 토큰 교환 | `POST /oauth/token` | 토큰 발급 실패 | PKCE 강제 |
| `mcp-006` | 성공 또는 redirect 가능한 오류 authorization response | client callback redirect | `iss` = metadata issuer | RFC 9207 mix-up 방어 |
| `mcp-token-001` | auth code 발급 후 `pending_deletion` 또는 `disabled/deleted`로 변경 | POST `/oauth/token` | `invalid_grant` | MCP 토큰 발급 시점 차단 |

## Refresh

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `refresh-001` | `active` | valid refresh_token | 새 access/refresh 발급 | 정상 rotation |
| `refresh-002` | `pending_deletion` | valid refresh_token | `invalid_grant` | 삭제 유예 차단 |
| `refresh-003` | `disabled` 또는 `deleted` | valid refresh_token | `invalid_grant` | 비활성 차단 |
| `refresh-004` | same token concurrent 2회 (유예 끔) | `/oauth/token` | 1회 성공 + 1회 실패 | row lock/원자성 |
| `refresh-004b` | same token 2회 (유예 5초) | `/oauth/token` | 2회 성공, 두 토큰 모두 rotation 가능, reuse 감사 0 | 동시 갱신 클라이언트 보호 |
| `refresh-005` | revoked token 재사용 | `/oauth/token` | family revoke + `invalid_grant` | 탈취 의심 처리 |
| `refresh-006` | 교환된 토큰을 유예 안에 재제출 | `Storage` | 같은 family에 새 토큰, tombstone 없음 | 유예 발급 |
| `refresh-007` | 교환된 토큰을 유예 밖에 재제출 | `Storage` | family revoke + tombstone | 유예 만료 |
| `refresh-008` | `/oauth/revoke`한 토큰을 유예 안에 재제출 | `Storage` | family revoke + tombstone | 폐기 토큰은 유예 없음 |
| `refresh-009` | 유예 안에서 상한(3개) 초과 재제출 | `Storage` | `invalid_grant`, family 유지 | 재생 발급 제한 |
| `refresh-010` | tombstone된 family 토큰을 유예 안에 재제출 | `Storage` | `invalid_grant` | 폐기 family 부활 금지 |
| `refresh-011` | 제출 10회가 모두 잠정 판정을 통과한 뒤 insert | `Storage` | 자식 총 3개, family 유지 | 잠금 하 상한 |
| `refresh-012` | 자식을 id로 revoke한 뒤 부모를 유예 안에 재제출 | `Storage` | `invalid_grant`, 살아있는 토큰 0, tombstone | 끝낸 세션 부활 금지 |
| `refresh-013` | 사용자 전체 revoke 뒤 부모를 유예 안에 재제출 | `Storage` | `invalid_grant`, 살아있는 토큰 0 | 〃 |
| `refresh-014` | 유예 형제가 있는 상태에서 한 토큰을 `/oauth/revoke`(hash·id) | `Storage` | 형제도 rotation 불가, 살아있는 토큰 0, tombstone `reason=revoked` | revoke = grant 전체 |
| `refresh-015` | 정상 교환과 유예 재생이 insert 순서를 바꿈 | `Storage` | `outcome=issued` 감사는 재생 IP 1건 | 감사 귀속 |
| `refresh-016` | insert 단계에서 상한 거부 | `Storage` | `invalid_grant`(→ 400), `ErrInvalidRefreshToken` 래핑 | 500 금지 |
| `refresh-017` | 교환된 토큰 행이 insert 전 삭제됨 | `Storage` | `invalid_grant`, 토큰 발급 없음 | 무관한 family 생성 금지 |
| `refresh-019` | 다른 클라이언트가 같은 family의 토큰(원문·id)으로 revoke | `Storage` | grant 유지, tombstone·감사 없음 | RFC 7009 클라이언트 바인딩 |
| `refresh-020` | 잠정 판정 뒤 계정 비활성화 / 토큰 만료 후 insert | `Storage` | `invalid_grant`, 자식 없음 | 잠금 하 재검증 |
| `refresh-018` | 교환 안 된 토큰에 20개 동시 요청 × 5회 | `Storage` | 자식 ≤ 3, 거부는 전부 `ErrInvalidRefreshToken`, 교착 없음 | 실제 동시성 |

## Delete / Recover

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `account-001` | `active` | `Storage.RequestDeletion` | `pending_deletion` | 상태 전이 |
| `account-002` | `pending_deletion` | `Storage.RequestDeletion` | 멱등 성공 | 재요청 무시 |
| `account-003` | `pending_deletion` | Browser 로그인 | active 복구 | 복구 경로 |
| `account-004` | `pending_deletion` | Device/MCP 로그인 | `account_inactive` | Browser만 복구 |
| `account-005` | `disabled` 또는 `deleted` | `Storage.RequestDeletion` | `ErrUserAccountClosed` | 비활성 계정 삭제 차단 |

## 검증 포인트

```text
1. Browser만 pending_deletion을 복구할 수 있는가?
2. Device/MCP는 active 사용자만 통과하는가?
3. Refresh는 active 상태에서만 허용되는가?
4. Delete/Recover가 상태기계를 깨지 않는가?
```
