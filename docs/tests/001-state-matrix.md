# Test 001: 상태 매트릭스

## 목적

`user.Status` 기반 상태 판정과 채널별 접근 제어가 스펙 전체에서 일관되게 적용되는지 검증한다.
상태 판정은 service 통합 테스트에서 검증한다.

## 상태 정의

```text
user.Status 기반 규칙
├─ 'disabled'           → 모든 채널 차단 (403 account_inactive)
├─ 'deleted'            → Browser는 신규 가입 재진입, 나머지는 차단
├─ 'pending_deletion'   → browser만 복구, 나머지 403
└─ 'active'             → 허용
```

## 공통 매트릭스

| user.Status | Browser | Device | MCP | Refresh | 기대 결과 |
|-------------|---------|--------|-----|---------|----------|
| `disabled` | 차단 | 차단 | 차단 | 차단 | 403 `account_inactive`, Refresh는 `invalid_grant` |
| `deleted` | 신규 가입 재진입 | 차단 | 차단 | 차단 | Browser는 Spec 001 재진입, 나머지는 차단 |
| `pending_deletion` | 복구 후 진행 | 차단 | 차단 | 차단 | Browser만 복구 허용, 나머지 403 |
| `active` | 허용 | 허용 | 허용 | 허용 | 정상 |

## service 통합 테스트 리스트

### 상태별 동작 검증

검증 위치: service 통합 테스트 (실 PostgreSQL + FixedClock)

| ID | user.Status | 기대 동작 | 검증 포인트 |
|----|-------------|----------|-------------|
| `status-001` | `disabled` | 모든 채널 403 | disabled는 항상 차단 |
| `status-002` | `deleted` | Browser는 신규 가입 재진입, 나머지는 차단 | deleted 종단 상태 + 브라우저 재가입 경로 |
| `status-003` | `pending_deletion` | browser만 복구, 나머지 403 | browser 복구 경로 확인 |
| `status-004` | `active` | 모든 채널 허용 | 정상 활성 계정 |

### 채널별 접근 제어 검증

검증 위치: service 통합 테스트 (실 PostgreSQL + FixedClock)

| ID | user.Status | Channel | 기대 결과 | 검증 포인트 |
|----|-------------|---------|----------|-------------|
| `channel-001` | `disabled` | browser | 403 `account_inactive` | Browser도 차단 |
| `channel-002` | `disabled` | device | 403 `account_inactive` | Device 차단 |
| `channel-002b` | `deleted` | browser | Spec 001 신규 가입 재진입 | Browser 재가입 경로 |
| `channel-003` | `pending_deletion` | browser | 복구 → active → 토큰 발급 | Browser 복구 |
| `channel-004` | `pending_deletion` | device | 403 `account_inactive` | Device 복구 불가 |
| `channel-005` | `pending_deletion` | mcp (세션 있음) | 403 `account_inactive` | MCP 세션 경로도 복구 불가 |
| `channel-006` | `pending_deletion` | mcp (콜백) | 403 `account_inactive` | MCP 콜백 경로도 복구 불가 |
| `channel-007` | `active` | browser | 토큰 발급 | 정상 허용 |
| `channel-008` | `active` | device | 토큰 발급 | 정상 허용 |
| `channel-009` | `active` | mcp | 토큰 발급 | 정상 허용 |

## 검증 포인트

```text
1. user.Status가 유일한 상태 판정 원천인가?
2. Browser / Device / MCP / Refresh가 같은 상태표를 공유하는가?
3. deleted는 Browser에서 신규 가입으로 재진입하고, 나머지 채널에서는 차단되는가?
4. pending_deletion은 Browser에서만 복구되는가? (세션 경로 + 콜백 경로 모두)
5. active 상태는 모든 채널에서 허용되는가?
```
