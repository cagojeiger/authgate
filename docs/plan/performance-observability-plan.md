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

완료 조건(검증 시나리오 기반):

1. 느린 upstream 모의(3~5초 지연)에서 요청이 timeout으로 종료되고 worker가 무한 대기하지 않음
2. DB 연결 상한 강제 상황에서 새 요청이 fail-fast 또는 제한된 대기 후 반환됨
3. 2개 이상 파드에서 cleanup가 동시에 실행되지 않음
4. SIGTERM 후 shutdown timeout 내 inflight 요청이 drain되거나 명시적 timeout으로 종료됨

## Phase 2: 관측성 기반(로그 + 기본 metrics)

범위:

- 공통 request logging middleware 추가
  - `request_id`, `method`, `path`, `status`, `duration_ms`
- 기본 metrics 도입 (`/metrics`)
  - counter: 요청 수, 에러 수
  - histogram: handler/DB/upstream 지연시간
  - gauge: inflight requests
- Upstream 호출 결과 로그/메트릭 표준화
  - `provider`, `operation(exchange/userinfo)`, `duration_ms`, `result`
- Cleanup 실행 로그/메트릭 표준화
  - job별 `duration_ms`, `affected_rows`, `result`

완료 조건:

1. 단일 요청의 로그와 메트릭이 같은 `path/status`로 상호 검증됨
2. 병목 발생 시 Handler/Upstream/DB 중 어디가 느린지 10분 내 구분 가능

## Phase 3: 부하 테스트 및 기준선 수립

범위:

- 핵심 플로우 부하 테스트
  - browser login callback
  - device approve/poll
  - token refresh
  - MCP authorize -> token (CIMD fetch 포함)
- 측정 지표
  - `p50/p95/p99 latency`
  - `error rate`
  - `timeout rate`
  - upstream 실패율

완료 조건:

1. 기준선 리포트 1회 작성(워크로드, 동시성, 기간, 결과 포함)
2. 느린 경로 Top N 확정

## Phase 4: 코드 경로 최적화

범위:

- 불필요한 DB round trip 감소
- cleanup 배치 처리(대량 delete/update 분할)
- audit write 전략 정리(동기 유지 또는 비동기 버퍼)

완료 조건:

- Phase 3 대비 p95 또는 timeout rate가 합의된 목표치 이상 개선

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

## Phase 6: 운영 고도화

범위:

- Prometheus 대시보드 구성
- 알람 규칙 설정(SLO 기반)
- 용량 계획 및 임계치 재조정

완료 조건:

- 대시보드와 알람만으로 성능 이상 징후 탐지 및 1차 대응 가능

## 작업 체크리스트

```text
[ ] Phase 1 완료
[ ] Phase 2 완료
[ ] Phase 3 완료
[ ] Phase 4 완료
[ ] Phase 5 완료 (인덱스)
[ ] Phase 6 완료 (운영 고도화)
```

## 의사결정 규칙

- 새로운 성능 이슈가 보여도 Phase를 건너뛰지 않는다.
- 인덱스는 항상 마지막에 검토한다.
- 각 Phase 종료 시 "측정 결과"를 남기고 다음 Phase로 이동한다.
