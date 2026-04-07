# 리팩토링 단계별 실행 계획

## 목적

authgate의 내부 코드를 "계층 재설계"가 아니라 "읽기 쉬운 구조 정리" 관점에서 단계적으로 다듬는다.

핵심 원칙은 다음과 같다.

- 아키텍처 경계는 [Architecture 001](../architecture/001-component-boundaries.md)을 유지한다.
- `storage`는 `zitadel/oidc`의 `op.Storage` 계약을 수용하는 코어로 본다.
- 리팩토링은 공개 동작 변경보다 내부 응집도 개선을 우선한다.
- 한 번에 모든 것을 바꾸지 않고, PR 단위로 검증 가능한 범위만 진행한다.
- 버그 수정/쿼리 최적화는 리팩토링과 분리된 트랙으로 먼저 처리한다.

## 리팩토링 대상 구분

```text
[유지해야 하는 경계]

[handler]
   |
   v
[service] -----------------> [upstream]
   |
   v
[storage(op.Storage)] -----> [sqlc/storeq]
   ^
   |
[adapter/mcp]  (optional adapter)
```

```text
[이번 계획에서 바꾸는 것]
- 긴 함수 분리
- helper / mapper / validation 분리
- 파일 책임 정리
- 테스트 가독성 보강

[이번 계획에서 바꾸지 않는 것]
- package 경계 재설계
- `op.Storage` 공개 계약 변경
- OAuth/OIDC 플로우 의미 변경
- examples / cmd 대규모 재구성
```

## 실행 순서

현재 코드는 다음 순서로 진행한다.

1. `Phase 0`: 버그 수정 + 쿼리 정리 (리팩토링 아님)
2. `Phase 1`: `internal/service` 리팩토링
3. `Phase 2`: `internal/adapter/mcp` 리팩토링 (조건부)
4. `Phase 3`: `internal/storage` 내부 리팩토링
5. `Phase 4`: `cmd/authgate`, `examples/*` 후속 정리

## 우선순위 근거

현재 코드 기준 우선순위는 다음과 같이 둔다.

1. `internal/service`
2. `internal/storage`
3. `internal/adapter/mcp` (조건부)
4. `cmd/authgate`, `examples/*`

이 순서를 택하는 이유:

- `service`는 built-in adapter 흐름 정리 효과가 즉시 크고 위험이 낮다.
- `storage`는 `op.Storage` 계약에 묶여 있으므로 가장 보수적으로 접근해야 한다.
- `adapter/mcp`는 optional adapter라 상태가 이미 양호하면 phase를 축소/생략할 수 있다.
- `cmd`, `examples`는 사용성 측면에서는 중요하지만 코어 복잡도 완화 우선순위는 낮다.

## PR 전략

```text
PR 1
[bugfix/query track]
  - id::text 캐스팅 버그
  - SQL 정리(sqlc 전환 포함)
  - contention/round-trip 이슈(선택)

PR 2
[service cleanup]
  - login/device/account 흐름 정리
  - helper 분리
  - 공개 동작 유지

PR 3 (optional)
[mcp adapter cleanup]
  - 필요 시에만 CIMD 읽기 경로 정리
  - MCP 관련 테스트 유지

PR 4
[storage internal cleanup]
  - op.Storage 메서드 시그니처 유지
  - token/device/users 내부 helper 분리
  - mapper/tx 보조 함수 정리

PR 5
[entrypoint follow-up]
  - cmd/authgate 조립 코드 정리
  - examples 최소 정리
```

각 PR은 다음 조건을 만족해야 한다.

- 기능 변경보다 구조 정리 목적이 명확해야 한다.
- 관련 테스트를 같은 PR에서 통과시켜야 한다.
- 다른 계층까지 번지는 리팩토링은 다음 PR로 미룬다.
- 버그 수정 PR과 리팩토링 PR은 분리한다.

## Phase 0: 버그 수정 + 쿼리 정리 (리팩토링 아님)

범위:

- `internal/storage` 및 연관 SQL
- 필요 시 `migrations`/`internal/db/queries`

목표:

- 이미 확인된 동작/쿼리 이슈를 먼저 제거한다.
- 이후 리팩토링에서 같은 파일을 재수정하는 비용을 줄인다.

기본 항목:

1. `id::text` 캐스팅 관련 버그 수정
2. cleanup batch SQL 정리 (가능하면 sqlc 경로로 통일)
3. `AuthRequestByCode` 불필요 round-trip 개선 (선택)
4. device polling `FOR UPDATE` contention 완화 (선택)

완료 조건:

1. 버그/쿼리 수정 PR은 동작 변경 의도가 명확히 기록된다.
2. 리팩토링 없이도 단독으로 리뷰/릴리즈 가능하다.
3. storage/integration 테스트가 유지된다.

## Phase 1: built-in adapter(service) 정리

범위:

- `internal/service/login.go`
- `internal/service/device.go`
- 필요 시 `internal/service/account.go`

목표:

- 메서드 하나가 전체 플로우를 모두 들고 있는 구조를 줄인다.
- "검증 / 조회 / 상태판단 / 세션발급 / 완료처리"를 helper로 분리한다.
- handler가 보는 반환 타입과 외부 동작은 유지한다.

완료 조건:

1. 각 메인 flow 함수의 단계가 이름 있는 helper로 분리된다.
2. service 패키지 테스트가 유지된다.
3. handler/service/storage 경계는 바뀌지 않는다.

## Phase 2: optional adapter(MCP) 정리 (조건부)

진입 조건:

- `cimd.go` 가독성 저하가 실제 리뷰 비용으로 확인될 때만 수행한다.
- 파일 분리보다 함수/테스트 보강이 더 낫다면 이 phase를 건너뛴다.

범위(수행 시):

- `internal/adapter/mcp/cimd.go` 또는 주변 helper 파일
- 관련 테스트 파일

목표:

- HTTP fetch
- 문서 파싱
- 문서 검증
- cache TTL 처리
- SSRF-safe transport

위 책임을 "파일 분리"가 아니라 "읽기 비용 감소" 관점으로 정리한다.

```text
현재
[cimd.go]
  ├─ transport
  ├─ fetch
  ├─ parse
  ├─ validate
  └─ cache

목표
[cimd fetcher]
  ├─ transport
  ├─ fetch
  ├─ validate
  └─ cache
```

완료 조건(수행 시):

1. CIMD 관련 테스트가 유지된다.
2. 외부 노출 타입(`HTTPCIMDFetcher`, `FetchClient`)은 유지된다.
3. SSRF 보호 및 캐시 동작 의미가 바뀌지 않는다.

## Phase 3: core storage 내부 정리

범위:

- `internal/storage/storage_auth_tokens.go`
- `internal/storage/storage_oidc_device.go`
- `internal/storage/users.go`
- 필요한 mapper/helper 파일

목표:

- `op.Storage` 구현 메서드는 그대로 유지한다.
- 메서드 내부의 tx 처리, row -> model 변환, refresh rotation/reuse detection 같은 세부 단계를 helper로 분리한다.
- "왜 큰가"를 줄이기보다 "왜 큰지 읽히게" 만드는 데 집중한다.
- Phase 0에서 정리된 쿼리/버그를 다시 건드리지 않도록 변경 축을 분리한다.

```text
[storage(op.Storage)]
   |
   +--> public contract method
           |
           +--> tx helper
           +--> state helper
           +--> mapper
           +--> audit helper
```

완료 조건:

1. `op.Storage` 계약 메서드 이름/시그니처는 유지된다.
2. storage integration test가 유지된다.
3. refresh token/device 관련 흐름이 helper 단위로 추적 가능해진다.

## Phase 4: 조립 코드 후속 정리

범위:

- `cmd/authgate/main.go`
- `examples/*`

목표:

- wiring 성격의 코드만 최소한으로 정리한다.
- 코어 리팩토링과 직접 관련 없는 대규모 구조 변경은 피한다.

완료 조건:

1. main 진입점은 조립 코드로서 읽기 쉬워진다.
2. examples는 동작 예시 역할을 유지한다.

## 작업 규칙

```text
해야 할 것
- 작은 PR로 나누기
- 각 단계마다 테스트 실행
- 경계 유지 여부를 PR 설명에 명시

하지 말 것
- service 로직을 storage로 밀어 넣기
- storage의 op.Storage 역할을 약화시키기
- adapter 책임을 core로 흘려보내기
- 리팩토링과 기능 추가를 같은 PR에 섞기
```

## 체크리스트

```text
[ ] Phase 0 완료 (bugfix/query track)
[ ] Phase 1 완료
[ ] Phase 2 완료 또는 skip 결정
[ ] Phase 3 완료
[ ] Phase 4 완료
```

## 의사결정 규칙

- "파일이 길다"만으로 쪼개지 않는다.
- "책임이 한 함수/파일 안에 과하게 섞여 있는가"를 기준으로 판단한다.
- `storage`는 일반 repository가 아니라 `op.Storage` 코어라는 점을 유지한다.
- 문서상 경계를 바꿔야 하는 리팩토링이면 plan이 아니라 architecture 문서를 먼저 수정한다.
- 버그 수정/성능 수정은 리팩토링 근거로 포장하지 않고 별도 PR로 다룬다.
