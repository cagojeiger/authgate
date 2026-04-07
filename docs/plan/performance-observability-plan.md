# 성능/관측성 단계별 실행 계획

## 목적

authgate의 성능 개선을 "측정 가능한 순서"로 진행한다.
핵심 원칙은 다음과 같다.

- 인덱스는 마지막 단계에서 적용한다.
- 먼저 런타임 안정화와 관측성을 확보한다.
- 변경마다 재측정해서 다음 단계를 결정한다.

## 컴포넌트 관점

```text
[Client]
   |
   v
[HTTP Handler]
   |
   v
[Service] --------------------------> [Upstream OIDC IdP]
   |                                      (network latency)
   v
[Storage(op.Storage)]
   |
   v
[sqlc]
   |
   v
[PostgreSQL]
```

성능 최적화 우선순위 경계:

1. `Handler <-> Service` (요청 시간/에러율/타임아웃)
2. `Service <-> Upstream` (외부 네트워크 지연)
3. `Service/Storage <-> DB` (쿼리 시간, 트랜잭션 길이)
4. 마지막에 인덱스

## Phase 0: 원칙 고정

목표:

- 인덱스 후순위 원칙을 팀 합의로 고정
- 본 문서를 기준으로 변경 순서 통일

완료 조건:

- PR/이슈에서 성능 작업이 본 문서 순서를 따름

## Phase 1: 런타임 하드닝

범위:

- HTTP 서버 타임아웃 설정
  - `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`
- DB 풀 설정
  - `SetMaxOpenConns`, `SetMaxIdleConns`, `SetConnMaxLifetime`, `SetConnMaxIdleTime`
- Upstream OIDC 호출 타임아웃 명시
- 멀티 파드 안전성
  - cleanup 작업의 단일 실행 보장(`advisory lock`)
  - 세션/토큰 상태가 파드 로컬 메모리에 의존하지 않음 확인
- graceful shutdown 개선
  - inflight request drain 확인
  - shutdown timeout 중 종료 실패 요청 수 관찰
- rate limiting 전략 결정
  - `/authorize`, `/oauth/token`, `/oauth/device/authorize` 보호 정책 정의
  - **결정: 앱 외부(리버스 프록시/API Gateway)에서 처리**. authgate 내부에 rate limit 코드를 넣지 않는다. 멀티 파드 환경에서 앱 내부 rate limit은 Redis 등 공유 저장소 의존성이 추가되어 복잡도만 올라가고, 프로덕션에서 앞단 게이트웨이 없이 배포하는 구성은 없기 때문이다.

완료 조건(검증 시나리오 기반):

1. 느린 upstream 모의(3~5초 지연)에서 요청이 timeout으로 종료되고 worker가 무한 대기하지 않음
2. DB 연결 상한 강제 상황에서 새 요청이 fail-fast 또는 제한된 대기 후 반환됨
3. 2개 이상 파드에서 cleanup가 동시에 실행되지 않음
4. SIGTERM 후 shutdown timeout 내 inflight 요청이 drain되거나 명시적 timeout으로 종료됨

## ~~Phase 2: 관측성 기반(로그 + 기본 metrics)~~ — 취소

운영 환경과 트래픽 규모가 구체화된 후 별도 계획으로 재설계한다.
관측성 범위(로그/metrics 분리 단위, Prometheus 도입 시점)를 먼저 확정해야 하므로 현 시점에서는 진행하지 않는다.

## ~~Phase 3: 부하 테스트 및 기준선 수립~~ — 취소

Phase 2와 동일한 사유로 보류. 운영 트래픽이 발생한 후 기준선 수립이 의미 있다.

## Phase 4: 코드 경로 최적화

범위:

- 불필요한 DB round trip 감소
- cleanup 배치 처리(대량 delete/update 분할)
- audit write 전략 정리(동기 유지 또는 비동기 버퍼)

식별 방법:

- 부하 테스트 없이 진행하므로, 코드 리뷰 기반으로 명확한 비효율을 찾아 수정한다.
- `pg_stat_statements` 또는 slow query log로 DB 레벨 병목을 관측한다.

완료 조건:

- 식별된 비효율 항목별 before/after 쿼리 수 또는 실행 시간 비교 기록

## Phase 5: 인덱스 최적화 (마지막)

원칙:

- Phase 4 실측 결과로 "필요한 최소 인덱스"만 추가
- 추측 기반 인덱스 추가 금지

절차:

1. 느린 쿼리 식별 (`pg_stat_statements`, `EXPLAIN ANALYZE`)
2. 후보 인덱스 제안
3. 적용 전/후 비교
4. 효과 없는 인덱스는 보류

완료 조건:

- 인덱스 추가 근거(측정값)와 효과(개선값)가 문서화됨

## 작업 체크리스트

```text
[x] Phase 1 완료
[-] Phase 2 취소 — 운영 환경 구체화 후 재설계
[-] Phase 3 취소 — 운영 트래픽 발생 후 재설계
[ ] Phase 4 완료
[ ] Phase 5 완료 (인덱스)
```

## 의사결정 규칙

- 새로운 성능 이슈가 보여도 Phase를 건너뛰지 않는다.
- 인덱스는 항상 마지막에 검토한다.
- 각 Phase 종료 시 "측정 결과"를 남기고 다음 Phase로 이동한다.
