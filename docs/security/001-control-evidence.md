# Security 001: Control Evidence Matrix

검토일: 2026-05-15

## 목적

authgate 서버가 한국 개인정보보호법(PIPA), 통신비밀보호법, SOC 2 Trust
Services Criteria, OAuth/OIDC 표준 등에 대해 제시할 수 있는 server-side
evidence를 한 곳에 매핑한다.

이 문서는 법률 의견서가 아니다. 보존기간, 정보주체 통지, 법적 예외,
소송 hold 같은 최종 판단은 운영/법무 정책에서 확정해야 한다. 여기서는
authgate 코드와 설정이 직접 생성하거나 검증할 수 있는 server-side evidence만
다룬다.

## 독자

감사관, 보안 컴플라이언스 담당자.

## 갱신 시점

- 새 control이 추가/변경됐을 때
- 인용 표준/조문이 바뀌었을 때
- 코드 위치(파일/라인)가 이동했을 때

## 증거 흐름

```text
HTTP request
  │
  ├─ clientinfo.Middleware
  │    └─ IP / User-Agent 추출
  │
  ├─ service layer
  │    └─ business event 결정
  │
  ├─ Storage.AuditLog
  │    ├─ event_type
  │    ├─ user_id
  │    ├─ ip_address
  │    ├─ user_agent
  │    ├─ metadata allowlist
  │    └─ best-effort INSERT
  │
  ▼
audit_log
  │
  ├─ append-only guard
  ├─ cleanup retention
  └─ PII anonymization after AUDIT_LOG_PII_RETENTION_DAYS
```

## 참조 기준

| 기준 | authgate에서의 해석 |
|------|------------------------|
| 개인정보 보호법 §29, §34 | 안전조치, 침해사고 조사, 통지 판단에 필요한 로그 근거 |
| 개인정보 보호법 시행령 제30조제1항제5호가목-다목 및 제30조제3항 | 접속기록 저장·점검·안전보관 및 위·변조 방지 조치의 직접 근거 |
| 개인정보의 안전성 확보조치 기준 (보호위원회 고시) 제8조제1항제1호-제3호 | 접속기록 1년/2년 보존기간의 직접 근거 |
| 통신비밀보호법 시행령 §41 | IP/접속시각 등 통신 메타데이터 보존기간 검토 기준 |
| SOC 2 Trust Services Criteria | CC6(접근통제), CC7(시스템 운영/탐지), CC8(변경관리) 증거 |
| ISMS-P 인증대상 기준 | 매출/이용자 임계 도달 시 별도 인증 범위 검토 기준 |

참고 URL:
- 개인정보 보호법: https://www.law.go.kr/LSW/lsInfoP.do?lsiSeq=248613
- 개인정보 보호법 시행령: https://www.law.go.kr/LSW/lsInfoP.do?lsId=011468
- 통신비밀보호법 시행령 §41: https://www.law.go.kr/LSW//lsLinkCommonInfo.do?lspttninfSeq=121362
- ISMS-P 인증대상: https://isms.kisa.or.kr/main/ispims/target/
- AICPA SOC: https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2

## 증거 수집 원칙

| 원칙 | authgate 적용 |
|------|---------------|
| 최소 수집 | audit metadata는 event별 allowlist만 저장 |
| 조사 가능성 | user_id, IP, User-Agent는 사고 조사 기간 동안 보존 |
| 보존 후 익명화 | `AUDIT_LOG_PII_RETENTION_DAYS` 이후 user_id/IP/User-Agent 제거 |
| 위변조 방지 | audit_log UPDATE/DELETE 제한 trigger |
| 실패 가시화 | audit write 실패는 metric으로 노출 |
| 변경관리 증거 | PR, CI, vulnerability check 결과를 SOC 2 evidence로 사용 |

## Control Matrix

### 개인정보보호법 (PIPA)

| ID | 요구/질문 | authgate evidence | 코드/문서 위치 | 테스트 위치 | 상태 |
|----|-----------|-------------------|----------------|-------------|------|
| KR-PIPA-LOG-001 | 개인정보처리시스템 접근/행위 기록을 남기는가 | `audit_log`에 `user_id`, `event_type`, `ip_address`, `user_agent`, `created_at` 저장 | `internal/storage/audit.go`, `docs/spec/007-data-model.md` | `internal/service/audit_test.go`, `internal/storage/audit_test.go` | DONE |
| KR-PIPA-LOG-002 | 개인정보 보호법 제29조, 시행령 제30조제1항제5호가목·나목 및 개인정보의 안전성 확보조치 기준 제8조제1항 본문에 따라 접속기록을 최소 1년 이상 보존하도록 fail-fast 설정하는가 | `AUDIT_LOG_PII_RETENTION_DAYS` 기본 1095일, 최소 365일 fail-fast | `internal/config/config.go:85`, `internal/config/config.go:120`, `README.md` | `internal/config/config_test.go:148`, `internal/config/config_test.go:245` | DONE |
| KR-PIPA-LOG-003 | 개인정보의 안전성 확보조치 기준 제8조제1항제1호-제3호의 2년 보존 대상 조건(5만명 이상 정보주체 / 고유식별·민감정보 처리 / 기간통신사업자)에 대응하여 730일 이상 설정할 수 있는가 | env로 730일 이상 설정 가능 | `internal/config/config.go:85` | `internal/config/config_test.go:148` | DONE |
| KR-PIPA-SEC-001 | 접속기록 위변조를 제한하는가 | audit_log append-only trigger, PII redaction 예외만 허용 | `migrations/003_audit_log_immutability.*.sql` | `internal/storage/audit_test.go` | DONE |
| KR-PIPA-SEC-002 | 불필요한 PII/secret이 audit metadata에 저장되지 않는가 | event별 metadata allowlist | `internal/storage/audit.go` | `internal/storage/audit_unit_test.go` | DONE |
| KR-PIPA-DEL-001 | 사용자 삭제/익명화 흐름을 추적할 수 있는가 | `auth.deletion_requested`, `auth.deletion_cancelled`, `auth.deletion_completed` | `internal/service/account.go`, `internal/service/login.go`, `internal/storage/cleanup_runner.go` | `internal/service/audit_test.go`, `internal/service/cleanup_test.go` | DONE |
| KR-PIPA-INC-001 | 침해 의심 이벤트를 조사할 수 있는가 | refresh token reuse와 family revoke 이벤트 | `internal/storage/storage_auth_tokens.go` | `internal/storage/audit_test.go` | DONE |
| KR-PIPA-INC-002 | audit log write 실패를 감지하는가 | `Storage.AuditLog` best-effort 실패 시 `slog.Error` 기록 | `internal/storage/audit.go`, `docs/spec/009-operations.md` | `internal/storage/audit_failure_unit_test.go` | DONE |

### 통신비밀보호법 (KR-COMM)

| ID | 요구/질문 | authgate evidence | 코드/문서 위치 | 테스트 위치 | 상태 |
|----|-----------|-------------------|----------------|-------------|------|
| KR-COMM-001 | IP/UA 등 접속 메타데이터를 추적할 수 있는가 | `audit_log.ip_address`, `audit_log.user_agent` | `internal/storage/audit.go`, `internal/clientinfo/*` | `internal/clientinfo/clientinfo_test.go` | DONE |

### SOC 2

| ID | 요구/질문 | authgate evidence | 코드/문서 위치 | 테스트 위치 | 상태 |
|----|-----------|-------------------|----------------|-------------|------|
| SOC2-CC6-001 | 민감한 console 조회 접근을 추적하는가 | console read/denied access audit events | `internal/service/console.go` | `internal/service/console_unit_test.go` | DONE |
| SOC2-CC6-002 | session/connection revoke 같은 권한성 작업을 추적하는가 | `auth.connection_revoked`, `auth.session_revoked`, `auth.other_sessions_revoked` | `internal/service/console.go` | `internal/service/console_unit_test.go` | DONE |
| SOC2-CC7-001 | 보안 이상징후를 탐지할 이벤트가 있는가 | inactive user access, refresh reuse detection, channel mismatch | `internal/service/*`, `internal/storage/storage_auth_tokens.go` | `internal/service/audit_test.go`, `internal/service/login_unit_test.go` | DONE |
| SOC2-CC7-002 | abuse 방어가 있는가 | per-IP rate limit for auth/token/callback/console endpoints, CIMD failure rate limit | `cmd/authgate/main.go`, `internal/middleware/ratelimit.go`, `internal/adapter/mcp/cimd.go` | `cmd/authgate/main_test.go`, `internal/integration/integration_ratelimit_test.go`, `internal/adapter/mcp/*ratelimit*_test.go` | DONE |
| SOC2-CC8-001 | 변경관리 evidence를 확보할 수 있는가 | GitHub PR, CI checks, vulnerability check | GitHub repository / Actions | PR checks | DONE |
| SOC2-CC8-002 | dependency vulnerability evidence가 있는가 | `govulncheck` local/CI 실행 | GitHub Actions, PR body | CI `Vulnerability Check` | DONE |

## 남은 GAP

| GAP | 설명 | 다음 작업 후보 |
|-----|------|----------------|
| GAP-OPS-001 | SOC 2 운영 evidence(PR 리뷰, access review, backup restore test)는 GitHub/운영 시스템에 존재해야 하며 authgate DB에는 저장하지 않는다. | 운영 evidence export/checklist 문서 |

## 완료 기준

이 문서의 `DONE` 항목은 다음 조건을 만족해야 한다.

```text
1. event_type 또는 운영 evidence 이름이 고정되어 있다.
2. 구현 위치가 명확하다.
3. 테스트 위치가 명확하다.
4. metadata에 저장하는 값이 최소화되어 있다.
5. 실패 시 silent하게 깨지는 통제는 metric 또는 CI로 감지된다.
```

새 control을 추가할 때는 이 문서와, 필요 시
[`002-event-catalog.md`](002-event-catalog.md)(새 event 추가),
[`003-endpoint-coverage.md`](003-endpoint-coverage.md)(새 endpoint),
[`docs/tests/004-audit-events.md`](../tests/004-audit-events.md)를 함께 갱신한다.
