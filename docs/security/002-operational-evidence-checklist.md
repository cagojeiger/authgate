# Security 002: Operational Evidence Checklist

검토일: 2026-05-15

## 목적

SOC 2 준비와 한국 개인정보보호법(PIPA) 운영 증적 중 authgate DB에 저장하지
않아야 하는 항목을 별도 체크리스트로 고정한다.

이 문서는 코드가 만드는 `audit_log`가 아니라, GitHub/운영 시스템/백업 저장소에
남겨야 하는 사람과 절차의 증거를 다룬다. authgate 서버는 이 증거의 일부 입력
자료를 제공하지만, 최종 보관 책임은 운영 절차에 있다.

```text
authgate 서버 증거
  |
  +-- audit_log
  +-- /metrics
  +-- CI / vulnerability check
  |
  v
운영 증적 패키지
  |
  +-- PR 리뷰 기록
  +-- access review 기록
  +-- backup restore test 기록
  +-- incident drill / postmortem 기록
```

## 보관 원칙

| 원칙 | 적용 |
|------|------|
| 시스템 분리 | 운영 증적은 authgate DB가 아니라 GitHub, 문서 저장소, ticket 시스템에 보관 |
| 위변조 추적 | 가능하면 Git commit, PR, issue, ticket처럼 변경 이력이 남는 위치 사용 |
| 최소 PII | 증적에는 이메일/사용자 ID 같은 식별자를 필요한 수준으로만 포함 |
| 재현 가능성 | 누가, 언제, 무엇을 확인했고, 어떤 결과였는지 남김 |
| 보존기간 | 회사 보안 정책에서 확정. SOC 2 준비 기준으로 최소 감사 기간 전체 보존 |

## 증적 목록

| ID | 증적 | 주기 | 보관 위치 | 포함할 내용 | 관련 통제 |
|----|------|------|-----------|-------------|-----------|
| OPS-CHANGE-001 | PR 리뷰 evidence | 모든 변경 | GitHub PR | reviewer, approval, CI 결과, merge commit | SOC2 CC8 |
| OPS-VULN-001 | 취약점 점검 evidence | 모든 PR + 월 1회 | GitHub Actions / 보안 ticket | `govulncheck` 결과, 실패 시 조치 ticket | SOC2 CC7 |
| OPS-ACCESS-001 | repository/admin access review | 분기 1회 | issue/ticket | 대상 시스템, 접근자, 권한, 유지/회수 결정, 승인자 | SOC2 CC6 |
| OPS-BACKUP-001 | DB backup restore test | 분기 1회 | issue/ticket + 복구 로그 | 백업 시점, 복구 환경, 성공/실패, RPO/RTO 메모 | SOC2 Availability |
| OPS-INCIDENT-001 | incident drill / postmortem | 반기 1회 또는 사고 후 | incident ticket | timeline, 영향, 의사결정, PIPA 72시간 판단, 후속 조치 | SOC2 CC7 / PIPA §34 |
| OPS-AUDIT-001 | audit log retention check | 분기 1회 | issue/ticket | `AUDIT_LOG_PII_RETENTION_DAYS`, cleanup 결과, 샘플 쿼리 | PIPA §29 / 시행령 §16 |

## 체크리스트 템플릿

### PR 리뷰

```text
Evidence ID: OPS-CHANGE-001
Period:
Repository:
PR:
Change summary:
Reviewer:
Required checks:
  - SQLC:
  - Test:
  - Go Vet:
  - Vulnerability Check:
Merge commit:
Notes:
```

### 접근권한 리뷰

```text
Evidence ID: OPS-ACCESS-001
Review date:
Reviewer:
Systems:
  - GitHub repository:
  - deployment secrets:
  - database/admin access:
Users reviewed:
  - user / role / decision / reason:
Revoked access:
Exceptions:
Follow-up tickets:
```

### 백업 복구 테스트

```text
Evidence ID: OPS-BACKUP-001
Test date:
Reviewer:
Backup source:
Backup timestamp:
Restore target:
Result:
RPO observed:
RTO observed:
Data checks performed:
Issues found:
Follow-up tickets:
```

### 사고 대응 훈련 / 사후 분석

```text
Evidence ID: OPS-INCIDENT-001
Date:
Scenario or incident:
Start time:
Detection source:
Systems affected:
Personal data impact:
PIPA 72h notification decision:
Timeline:
Actions taken:
Owner:
Follow-up tickets:
```

### audit log 보존 점검

```text
Evidence ID: OPS-AUDIT-001
Review date:
Environment:
AUDIT_LOG_PII_RETENTION_DAYS:
Cleanup job status:
Sample queries:
  - oldest audit_log row:
  - newest anonymized audit_log row:
  - recent audit write failure metric:
Result:
Follow-up tickets:
```

## 운영 절차와 서버 증거의 연결

| 운영 증적 | authgate에서 확인할 수 있는 입력 |
|-----------|----------------------------------|
| PR 리뷰 | GitHub PR checks, merge commit, `go test`, `go vet`, `govulncheck` |
| 취약점 점검 | CI `Vulnerability Check`, local `govulncheck` |
| 접근권한 리뷰 | GitHub 권한, 배포/DB 권한. authgate DB에는 저장하지 않음 |
| 백업 복구 테스트 | PostgreSQL backup/restore 결과. authgate는 `/ready`와 DB schema로 복구 검증 |
| 사고 대응 | `audit_log`, `authgate_audit_log_write_failures_total`, HTTP metrics |
| audit 보존 점검 | `AUDIT_LOG_PII_RETENTION_DAYS`, cleanup 로그, `audit_log` 샘플 |

## 범위 밖

아래 항목은 회사 정책이나 법무 판단 문서에서 확정한다.

- 정보주체 통지 문안
- 법적 보존 예외와 legal hold
- 고객/감독기관 보고 승인권자
- 공식 SOC 2 auditor 요청 양식
- ISMS-P 의무 대상 여부의 최종 판단
