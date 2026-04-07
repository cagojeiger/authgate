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

완료 조건:

- 과도한 hanging request가 재현되지 않음
- DB 연결 고갈 상황에서 fail-fast 동작 확인

## Phase 2: 로그 기반 관측성

범위:

- 공통 request logging middleware 추가
  - `request_id`, `method`, `path`, `status`, `duration_ms`
- Upstream 호출 결과 로그 표준화
  - `provider`, `operation(exchange/userinfo)`, `duration_ms`, `result`
- Cleanup 실행 로그 표준화
  - job별 `duration_ms`, `affected_rows`

완료 조건:

- 문제 상황에서 로그만으로 병목 구간(Handler/Upstream/DB) 식별 가능

## Phase 3: 부하 테스트 및 기준선 수립

범위:

- 핵심 플로우 부하 테스트
  - browser login callback
  - device approve/poll
  - token refresh
- 측정 지표
  - `p50/p95/p99 latency`
  - `error rate`
  - `timeout rate`

완료 조건:

- 기준선 리포트 1회 작성
- 느린 경로 Top N 확정

## Phase 4: 코드 경로 최적화

범위:

- 불필요한 DB round trip 감소
- cleanup 배치 처리(대량 delete/update 분할)
- audit write 전략 정리(동기 유지 또는 비동기 버퍼)

완료 조건:

- Phase 3 대비 p95 감소 또는 timeout rate 감소

## Phase 5: 인덱스 최적화 (마지막)

원칙:

- Phase 3/4 실측 결과로 "필요한 최소 인덱스"만 추가
- 추측 기반 인덱스 추가 금지

절차:

1. 느린 쿼리 식별
2. 후보 인덱스 제안
3. 적용 전/후 부하테스트 비교
4. 효과 없는 인덱스는 보류

완료 조건:

- 인덱스 추가 근거(측정값)와 효과(개선값)가 문서화됨

## Phase 6: Prometheus 도입

범위:

- `/metrics` 노출
- 지표 추가
  - counter: 요청 수, 에러 수
  - histogram: handler/DB/upstream 지연시간
  - gauge: inflight requests
- 대시보드/알람 연결

완료 조건:

- 로그 없이도 대시보드에서 성능 이상 징후를 탐지 가능

## 작업 체크리스트

```text
[ ] Phase 1 완료
[ ] Phase 2 완료
[ ] Phase 3 완료
[ ] Phase 4 완료
[ ] Phase 5 완료 (인덱스)
[ ] Phase 6 완료 (Prometheus)
```

## 의사결정 규칙

- 새로운 성능 이슈가 보여도 Phase를 건너뛰지 않는다.
- 인덱스는 항상 마지막에 검토한다.
- 각 Phase 종료 시 "측정 결과"를 남기고 다음 Phase로 이동한다.
