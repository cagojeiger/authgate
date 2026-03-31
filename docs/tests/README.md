# authgate 테스트 문서

## 개요

이 디렉토리는 authgate의 상태기계와 로그인/토큰/계정 lifecycle을 검증하기 위한 테스트 설계 문서를 담는다.
목표는 "어떤 상태에서 어떤 채널로 진입하면 무엇이 되어야 하는가"를 고정하는 것이다.

## 문서 목록

| # | 문서 | 목적 |
|---|------|------|
| 001 | [상태 매트릭스](001-state-matrix.md) | `user.Status` 기반 상태 판정과 채널별 접근 제어 검증 |
| 002 | [채널 플로우 테스트](002-channel-flows.md) | Browser / Device / MCP / Refresh / Delete 플로우별 검증 |
| 003 | [E2E 사이클 테스트](003-e2e-cycles.md) | 가입 → 사용 → 탈퇴 → 복구/삭제 → 재가입 전체 사이클 검증 |
| 004 | [감사 이벤트 테스트](004-audit-events.md) | `audit_log.event_type`와 metadata 기록 검증 |
| 005 | [Upstream Provider 테스트](005-upstream-provider.md) | OIDCProvider discovery/exchange/userinfo 검증 |

## 구조

```text
1. 상태 판정이 맞는가?
   -> 001-state-matrix.md

2. 각 채널이 같은 규칙을 따르는가?
   -> 002-channel-flows.md

3. 시작부터 끝까지 사이클이 닫히는가?
   -> 003-e2e-cycles.md

4. 중요한 보안/운영 이벤트가 빠짐없이 기록되는가?
   -> 004-audit-events.md
```

## 실행 메모

```text
문서 = 테스트 설계
코드 = internal/*_test.go

- config/clock/idgen 일부는 일반 unit test로 바로 실행 가능
- service/storage/integration 테스트 다수는 `//go:build integration`
- integration 테스트는 testcontainers-go를 사용하므로 Docker 접근 권한이 필요
```

## 테스트 원칙

1. 각 테스트는 **초기 상태**, **입력**, **기대 결과**, **검증 포인트**를 반드시 가진다.
2. `user.Status` 기반 상태 판정은 모든 채널 테스트의 source of truth다.
3. Browser / Device / MCP / Refresh는 서로 다른 구현이 아니라 **동일 상태기계의 다른 진입점**으로 검증한다.
4. `pending_deletion`은 Browser에서만 복구 가능함을 반드시 검증한다.
5. `deleted`는 종단 상태이며, 재가입은 반드시 신규 가입으로 다시 시작해야 한다.
