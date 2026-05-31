# Architecture Notes

이 디렉토리는 authgate 내부 패키지 경계와 책임 변경을 기록한다.

## Notification Package

`internal/notification`은 Slack 알림과 주간 리포트를 소유한다.

책임:
- 선택된 `audit_log` 이벤트를 `notification_outbox`에 적재
- PostgreSQL advisory lock으로 멀티 replica 단일 sender 실행
- Slack incoming webhook 전송 및 실패 재시도 상태 관리
- `notification_report_runs`로 주간 리포트 중복 발송 방지

비책임:
- 인증/인가 결정
- audit event의 source-of-truth 역할
- Prometheus/Alertmanager 기반 장애 알림

`internal/storage`는 Slack을 import하지 않는다. storage는 `AuditHook` 인터페이스만 제공하고, app wiring에서 notification enqueuer를 주입한다. Slack 알림을 제거하려면 app wiring, `internal/notification`, notification 마이그레이션만 제거하면 인증 도메인 로직은 남는다.
