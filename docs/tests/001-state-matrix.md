# Test 001: 상태 매트릭스

## 목적

`DeriveLoginState(user)`와 `GuardLoginChannel(user, channel)`의 공통 판정이 스펙 전체에서 일관되게 적용되는지 검증한다.

## 상태 정의

```text
DeriveLoginState(user)
├─ inactive
├─ recoverable_browser_only
├─ initial_onboarding_incomplete
├─ reconsent_required
└─ onboarding_complete
```

## 공통 매트릭스

| 현재 상태 | Browser | Device | MCP | Refresh | 기대 결과 |
|----------|---------|--------|-----|---------|----------|
| `inactive` | 차단 | 차단 | 차단 | 차단 | Browser/Device/MCP는 `account_inactive`, Refresh는 최종적으로 `invalid_grant` |
| `recoverable_browser_only` | 복구 후 진행 | 차단 | 차단 | 차단 | Browser만 복구 허용, Refresh는 최종적으로 `invalid_grant` |
| `initial_onboarding_incomplete` | 약관 페이지 | 차단 | 차단 | 차단 | Browser만 온보딩 계속, Refresh는 최종적으로 `invalid_grant` |
| `reconsent_required` | 약관 재동의 | 차단 | 차단 | 차단 | Browser만 재동의 허용, Refresh는 최종적으로 `invalid_grant` |
| `onboarding_complete` | 허용 | 허용 | 허용 | 허용 | 정상 |

## 단위 테스트 리스트

### DeriveLoginState

| ID | 초기 데이터 | 기대 상태 | 검증 포인트 |
|----|------------|----------|-------------|
| `state-001` | `status='disabled'` | `inactive` | disabled는 항상 inactive |
| `state-002` | `status='deleted'` | `inactive` | deleted는 항상 inactive |
| `state-003` | `status='pending_deletion'` | `recoverable_browser_only` | 브라우저만 복구 가능 |
| `state-004` | `status='active'`, `terms_accepted_at=NULL` | `initial_onboarding_incomplete` | 최초 가입 미완료 |
| `state-005` | `status='active'`, `privacy_accepted_at=NULL` | `initial_onboarding_incomplete` | privacy만 비어 있어도 미완료 |
| `state-006` | accepted_at 존재, `terms_version != CURRENT_TERMS_VERSION` | `reconsent_required` | 버전 불일치 |
| `state-007` | accepted_at 존재, `privacy_version != CURRENT_PRIVACY_VERSION` | `reconsent_required` | privacy 버전 불일치 |
| `state-008` | `status='active'`, accepted_at 존재, 버전 일치 | `onboarding_complete` | 정상 상태 |

### GuardLoginChannel

| ID | DeriveLoginState | Channel | 기대 결과 | 검증 포인트 |
|----|------------------|---------|----------|-------------|
| `guard-001` | `inactive` | `browser` | `account_inactive` | Browser도 차단 |
| `guard-002` | `inactive` | `device` | `account_inactive` | Device 차단 |
| `guard-003` | `recoverable_browser_only` | `browser` | `recover_then_continue` | Browser 복구 |
| `guard-004` | `recoverable_browser_only` | `device` | `account_inactive` | Device 복구 불가 |
| `guard-005` | `initial_onboarding_incomplete` | `browser` | `show_terms` | Browser만 약관 |
| `guard-006` | `initial_onboarding_incomplete` | `mcp` | `signup_required` | MCP 차단 |
| `guard-007` | `reconsent_required` | `browser` | `show_terms` | 재동의 |
| `guard-008` | `reconsent_required` | `refresh` | `signup_required` | guard 레벨에서는 refresh도 차단 상태로 판정, 최종 OAuth 응답은 별도 refresh 테스트에서 `invalid_grant` 검증 |
| `guard-009` | `onboarding_complete` | `browser` | `allow` | 정상 허용 |
| `guard-010` | `onboarding_complete` | `device` | `allow` | 정상 허용 |

## 검증 포인트

```text
1. DeriveLoginState가 유일한 상태 판정 원천인가?
2. Browser / Device / MCP / Refresh가 같은 상태표를 공유하는가?
3. initial_onboarding_incomplete와 reconsent_required가 구분되는가?
4. recoverable_browser_only는 Browser에서만 복구되는가?
```
