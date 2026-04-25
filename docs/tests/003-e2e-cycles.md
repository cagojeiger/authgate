# Test 003: E2E 사이클 테스트

## 목적

authgate의 핵심 철학인 "가입 → 사용 → 탈퇴 → 복구/삭제 → 재가입" 전체 사이클이 닫혀 있는지 검증한다.

## 사이클 다이어그램

```text
[미가입]
   |
   | Browser 가입
   v
[active]
   |
   | DELETE /account
   v
[pending_deletion]
   |
   +--> Browser 로그인 -> 복구 -> [active]
   |
   +--> 30일 경과 cleanup -> [deleted]
                              |
                              | 같은 IdP 계정으로 Browser 로그인
                              v
                           [미가입처럼 처리]
```

## 필수 E2E 시나리오

### E2E 1: 최초 가입부터 정상 사용까지

| 단계 | 입력 | 기대 결과 | 검증 포인트 |
|------|------|----------|-------------|
| 1 | 미가입 IdP 사용자 Browser 로그인 | Spec 001 진입 | Browser만 가입 |
| 2 | 가입 완료 | `active` | 정상 완료 |
| 3 | 동일 사용자 Browser 재로그인 | auto-approve | 기존 유저 경로 |
| 4 | 동일 사용자 Device 로그인 | 성공 | 후속 채널 허용 |
| 5 | 동일 사용자 MCP 로그인 | 성공 | 후속 채널 허용 |

### E2E 2: 가입 중 이탈 후 복귀

| 단계 | 입력 | 기대 결과 | 검증 포인트 |
|------|------|----------|-------------|
| 1 | 미가입 사용자 Browser 로그인 | users + user_identities 생성 | 가입 시작 |
| 2 | 가입 플로우 이탈 | 계정 미완료 상태 유지 | 중간 상태 존재 가능 |
| 3 | Browser 재로그인 | 정상 로그인 진행 | 계속 진행 가능 |
| 4 | Device/MCP 로그인 시도 | `account_not_found` 또는 `account_inactive` | Browser 외 차단 |

### E2E 3: 탈퇴 후 복구

| 단계 | 입력 | 기대 결과 | 검증 포인트 |
|------|------|----------|-------------|
| 1 | `active` 사용자 | `DELETE /account` | `pending_deletion` |
| 2 | Refresh 시도 | `invalid_grant` | 즉시 차단 |
| 3 | Device/MCP 로그인 시도 | `account_inactive` | Browser만 복구 가능 |
| 4 | Browser 로그인 | active 복구 + 새 세션 | 복구 성공 |
| 5 | 다시 Refresh/Device/MCP | 정상 동작 | 복구 후 정상화 |

### E2E 4: 탈퇴 후 최종 삭제와 재가입

| 단계 | 입력 | 기대 결과 | 검증 포인트 |
|------|------|----------|-------------|
| 1 | `active` 사용자 | `DELETE /account` | `pending_deletion` |
| 2 | 30일 경과 + deletion cleanup | `user_identities/sessions/refresh_tokens` 삭제 + `users.status='deleted'` | 명시적 cleanup |
| 3 | 같은 IdP 계정으로 Browser 로그인 | 기존 계정과 매칭되지 않음 | 기존 계정 아님 |
| 4 | Spec 001 신규 가입 서브플로우 진입 | 새 `user_id` 발급 | deleted row와 분리 |
| 5 | 가입 완료 | `active` | 새 계정 |

### E2E 5: 복구 후 로그인 완료 실패와 재시도

| 단계 | 입력 | 기대 결과 | 검증 포인트 |
|------|------|----------|-------------|
| 1 | `pending_deletion` 사용자 | Browser 로그인 | active 복구 + 세션 생성 |
| 2 | auth_request 완료 상태 반영 또는 후속 로그인 완료 단계 실패 | 이번 시도 실패 | 복구는 유지 |
| 3 | 동일 사용자가 다시 Browser 로그인 | 즉시 정상 완료 | 재시도 멱등성 |

### E2E 6: cleanup job 멱등성

| 단계 | 입력 | 기대 결과 | 검증 포인트 |
|------|------|----------|-------------|
| 1 | `pending_deletion`, 30일 경과 | deletion cleanup 1회 실행 | identities/sessions/tokens 삭제 + users scrub |
| 2 | 동일 cleanup 재실행 | 추가 손상 없음 | 멱등 |

### E2E 7: cleanup job 롤백

| 단계 | 입력 | 기대 결과 | 검증 포인트 |
|------|------|----------|-------------|
| 1 | `pending_deletion`, 30일 경과 | deletion cleanup 실행 중 중간 실패 | 전체 롤백 |
| 2 | DB 재조회 | 일부만 삭제된 상태 없음 | 단일 트랜잭션 보장 |

## 사이클 불변식

```text
1. 가입은 Browser에서만 시작한다.
2. Device/MCP는 신규 가입을 발생시키지 않는다.
3. pending_deletion은 Browser만 복구할 수 있다.
4. deleted는 종단 상태이며 재활성화되지 않는다.
5. 재가입은 항상 새 user_id를 갖는 신규 가입이다.
```

## 회귀 테스트 우선순위

| 우선순위 | 테스트 |
|---------|--------|
| P0 | E2E 1, E2E 3, E2E 4, E2E 5 |
| P1 | E2E 2, E2E 6 |
| P2 | E2E 7, race condition 및 audit 검증 |
