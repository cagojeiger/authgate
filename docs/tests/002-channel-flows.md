# Test 002: 채널 플로우 테스트

## 목적

Browser / Device / MCP / Refresh / Logout / Delete 각 채널이 공통 상태기계를 깨지 않고 동작하는지 검증한다.

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
| `signup-domain-006` | `*.example.com` 설정 | `sub.example.com` / `example.com` / `notexample.com` | 순서대로 허용 / 거부 / 거부 | 와일드카드는 라벨 경계를 지키고 상위 도메인을 포함하지 않음 |
| `signup-domain-007` | `*.example.com`, `korp.com` 설정 | `a@.example.com`, `a@..example.com`, 켈빈 기호 `K`orp.com, 끝 공백 | `email_malformed` 거부 | 이메일 도메인도 ASCII DNS 이름이어야 함 |
| `signup-domain-008` | `*.example.com` 설정 | 대문자 주소 / 미검증 주소 | 허용 / `email_unverified` | 와일드카드도 대소문자 무시·검증 요구 |
| `signup-domain-100` | 미가입, `SIGNUP_EMAIL_DOMAINS` 밖 도메인 | 실제 `/login/callback` | 403, `users` 0, `auth.signup` 0, `auth.signup_denied` 1(user_id null, domain) | 계정 생성 **전** 차단 (통합) |
| `signup-domain-101` | 미가입, 허용 도메인 | 실제 Browser 로그인 | 토큰 발급 | 게이트가 정상 가입을 막지 않음 (통합) |
| `signup-domain-102` | 기존 `active`, 도메인 목록 밖 | Browser 로그인 | 정상 로그인 | 가입만 제한 — 기존 계정 잠기지 않음 |

### prompt 파라미터 (Browser / MCP 공통)

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `login-prompt-001` | `active` 세션 | `prompt=none` → `/login`, `/mcp/login` | auto-approve | 세션 재사용 유지 |
| `login-prompt-002` | 세션 없음 | `prompt=none` → `/login`, `/mcp/login` | `redirect_uri?error=login_required&state&iss`, 기존 query 유지 | IdP·화면 없음 |
| `login-prompt-003` | Browser `disabled`/`deleted`, MCP `disabled`/`pending_deletion` 세션 | `prompt=none` | `login_required` + `auth.inactive_user` 1건 | 403 화면 대신 오류 응답 |
| `login-prompt-004` | mcp 클라이언트 auth_request | `prompt=none` → `/login` | `channel_mismatch` 화면 | 채널 검증이 redirect보다 먼저 |
| `login-prompt-005` | `active` 세션 | `prompt=login`, `select_account`, `login consent` | IdP redirect + upstream `prompt=select_account`, 세션 조회 없음 | 세션 재사용 안 함 |
| `login-prompt-006` | `active` 세션 / 세션 없음 | prompt 없음, `consent` | auto-approve / upstream prompt 없는 IdP redirect | 기존 동작 |
| `login-prompt-007` | - | `Storage.CreateAuthRequest`(prompt 있음/없음) | `GetAuthRequestModel`에서 같은 값, 없음은 빈 배열 | prompt 저장 |
| `login-prompt-008` | `pending_deletion` 세션 (browser) | `prompt=none` | `login_required`, 복구·완료 없음, `auth.inactive_user` 1 | 백그라운드 확인이 탈퇴를 취소하지 않음 |
| `login-prompt-009` | 만료된 auth_request (browser/mcp) | `/login` | 400 `auth_request_expired` | 만료는 500이 아님 |
| `browser-prompt-001` / `mcp-prompt-001` | 로그인 후 세션 쿠키 | `/authorize?prompt=select_account` → 로그인 경로 | `/fake-auth?...&prompt=select_account` | 실제 서버에서 세션 재사용 안 함 |
| `browser-prompt-002` / `mcp-prompt-002` | 세션 없음 | `/authorize?prompt=none` → 로그인 경로 | `302 /callback?error=login_required&state=test-state&iss=<issuer>` | RFC 9207 `iss` |
| `browser-prompt-003` / `mcp-prompt-003` | 로그인 후 세션 쿠키 | `/authorize?prompt=none` | code 발급 + 토큰 교환 성공 | 무화면 로그인 |
| `browser-prompt-004` | - | `/authorize?prompt=none login` | `invalid_request`, 로그인 경로로 가지 않음 | zitadel 검증 |

단위 테스트(`login-prompt-001`~`006`, `008`, `009`)는 `internal/service/login_unit_test.go`, `login-prompt-007`은
`internal/storage/codes_integration_test.go`, `*-prompt-00N` 통합 테스트는 `internal/integration/integration_prompt_test.go`에 있다.

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

## Logout

`/end_session` (OIDC RP-Initiated Logout 1.0). 통합 테스트는 `internal/integration/integration_logout_test.go`, 핸들러 단위 테스트는 `internal/handler/logout_test.go`.

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|------------|
| `logout-001` | 세션 없음 | `GET /end_session` (hint 없음) | 200 로그아웃 완료 페이지, 리다이렉트 없음, `auth.logout` 0 | 종료할 것 없음 |
| `logout-002` | 유효 세션 | `GET /end_session` (hint 없음) | 200 확인 페이지 + `csrf_token`, 세션 유지 | §2 확인 필수 |
| `logout-003` | 유효 세션 | 확인 POST (CSRF 일치) | 세션 폐기, `authgate_session` 만료, `auth.logout` 1, 다음 `/login`은 IdP로 | 계정 전환 경로 |
| `logout-004` | 유효 세션 | 확인 POST (CSRF 누락/불일치) | 403, 세션 유지, `auth.logout` 0 | CSRF 방어 |
| `logout-005` | 유효 세션 | `id_token_hint` = 세션 사용자 | 확인 없이 종료, 쿠키 만료, `auth.logout.client_id` = hint `azp` | hint가 확인을 대신 |
| `logout-006` | 사용자 B 세션 | `id_token_hint` = 사용자 A | 확인 페이지, 확인 POST 후 B 세션만 폐기(A 유지), `auth.logout` 1 | 다른 사용자 hint는 증거가 아님 |
| `logout-007` | 유효 세션 | 서명 불일치/형식 오류 `id_token_hint` | 400, 세션 유지 | hint 검증 |
| `logout-008` | 사용자 세션(다른 브라우저) | 쿠키 없이 유효한 `id_token_hint` | 완료 페이지, 세션 유지, `auth.logout` 0 | hint만으로 로그아웃 불가 |
| `logout-009` | — | 쿠키 없는 POST | 200, `authgate_session`/`end_session_csrf` Set-Cookie 없음 | 교차 사이트 POST 강제 로그아웃 차단 |
| `logout-010` | 유효 세션 | `confirm` 없는 POST | 확인 페이지, 세션 유지 | RP의 POST 요청은 확인이 아님 |
| `logout-011` | 유효 세션 | 세션 사용자 hint + 미등록 `post_logout_redirect_uri` | 로그아웃 완료 페이지, 리다이렉트 없음, 세션 폐기 | 미등록 URI는 버리고 로그아웃 계속 |
| `logout-012` | 유효 세션 | hint + `azp`와 다른 `client_id` | 400, 세션 유지 | 클라이언트 일치 |
| `logout-013` | 비활성화된 계정 세션 | 확인 POST | 세션 폐기, 쿠키 만료 | 비활성 계정도 로그아웃 |
| `logout-014` | 유효 세션 | 같은 hint로 3회 | `auth.logout` 1 | 종료한 것이 없으면 감사 없음 |
| `logout-015` | 세션 1개 | `Storage.TerminateSession` 3회 | `auth.logout` 1 | 영향 행 0이면 감사 없음 |
| `logout-unit-001` | 유효 세션 | `GET` (hint 없음) | 확인 페이지, CSRF 쿠키 `Strict`/`HttpOnly`/`Secure`/Path=`/end_session` | 쿠키 속성 |
| `logout-unit-002` | 유효 세션 | 확인 POST (폼 토큰 누락/쿠키 누락/불일치) | 403, 종료 호출 없음, 세션 쿠키 미변경 | CSRF 가드 |
| `logout-unit-003` | 유효 세션 | 확인 POST (CSRF 일치) | 종료 1회, 세션·CSRF 쿠키 만료 | 쿠키 삭제 |
| `logout-unit-004` | — | 등록된 `post_logout_redirect_uri` + `client_id` + `state` | 302 `…?state=` | §3 리다이렉트 |
| `logout-unit-005` | — | `client_id` 없이 `post_logout_redirect_uri` + `state` | 200 완료 페이지, 리다이렉트 없음 | 미검증 URI·빈 URL 리다이렉트 금지 |
| `logout-unit-006` | 유효 세션 | 미등록 `post_logout_redirect_uri` + `client_id` | 확인 페이지, 리다이렉트·종료 없음 | open redirect 차단, 로그아웃은 계속 |
| `logout-unit-007` | 세션 조회 오류 | GET → 확인 POST | 확인 페이지 → 세션 쿠키 만료 | 장애 시에도 이 브라우저 로그아웃 |
| `logout-unit-008` | — | 쿠키 없는 POST | Set-Cookie 없음 | 가져오지 않은 쿠키는 지우지 않음 |
| `session-cookie-003` | — | `clearSessionCookie` | 발급과 같은 속성 + `Max-Age<0` | 브라우저가 같은 쿠키로 인식 |

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
5. 로그아웃은 증거(일치하는 id_token_hint) 또는 사용자 확인이 있을 때만 세션을 끝내는가?
```
