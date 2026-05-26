# Security 001: 서비스 감사로그 및 증거 설계

검토일: 2026-05-26
상위 기준: [Security 000: 서비스 보안 설계 기준](000-security-baseline.md)

## 목적

이 문서는 authgate 서비스가 직접 생성하는 감사로그와 보안 증거를 정의한다.
운영자 접근권한 리뷰, 백업 복구 훈련, SOC 2 감사기간 증거, ISMS-P 인증 심사
자료는 범위 밖이다.

감사로그의 목적은 다음이다.

- 인증/토큰/계정/console 보안 이벤트 조사
- 개인정보처리시스템 접속기록 보존 및 위변조 방지 기준 반영
- SOC 2/ISMS-P에 매핑 가능한 서비스 증거 생성
- secret/token 원문 저장 없이 필요한 사실만 기록

## 감사로그 데이터 계약

| 필드 | 의미 | 기준 |
|------|------|------|
| `id` | append-only row id | 수정/삭제 금지 |
| `user_id` | 관련 user id, 없으면 NULL | 보존기간 후 NULL redaction 허용 |
| `event_type` | 고정 이벤트 이름 | 수정 금지 |
| `ip_address` | 요청 IP | 보존기간 후 NULL redaction 허용 |
| `user_agent` | 요청 User-Agent | 보존기간 후 NULL redaction 허용 |
| `metadata` | event별 allowlist payload | 수정 금지, secret/token 원문 금지 |
| `created_at` | 이벤트 발생 시각 | 수정 금지 |

구현 근거:

- `migrations/001_init.up.sql`: `audit_log` schema
- `migrations/003_audit_log_immutability.up.sql`: append-only guard
- `internal/storage/audit.go`: metadata allowlist와 best-effort insert
- `internal/db/queries/cleanup.sql`: PII redaction

## 보존 및 위변조 기준

| 기준 | 서비스 설계 |
|------|-------------|
| 최소 보존 | `AUDIT_LOG_PII_RETENTION_DAYS >= 365`를 config에서 강제한다. |
| 기본 보존 | 기본값은 1095일이다. |
| 2년 조건 | 5만명 이상 정보주체 처리, 민감정보/고유식별정보 처리 등 2년 보존 조건에 대비해 730일 이상 설정 가능해야 한다. |
| 보존 후 처리 | `user_id`, `ip_address`, `user_agent`를 NULL로 redaction한다. |
| 위변조 방지 | `event_type`, `metadata`, `created_at`, `id`는 UPDATE/DELETE를 차단한다. |
| 실패 처리 | audit insert 실패는 business flow를 실패시키지 않고 error log로 드러낸다. |

## Metadata 최소화 기준

| 기준 | 적용 |
|------|------|
| allowlist 방식 | event type별 허용 key만 저장한다. |
| unknown event | allowlist가 없는 event의 metadata는 저장하지 않는다. |
| secret 금지 | access token, refresh token 원문, client secret, OIDC code, session secret은 저장하지 않는다. |
| 식별자 제한 | 조사에 필요한 session_id, family_id, client_id 같은 내부 식별자만 event별로 제한해 저장한다. |
| 실패 로그 제한 | audit write 실패 로그에는 metadata payload를 포함하지 않는다. |

## Event Matrix

| event_type | 서비스 트리거 | 주요 증거 | metadata allowlist | 기준 |
|------------|---------------|-----------|--------------------|------|
| `auth.signup` | 브라우저 신규 가입 | user_id, IP, UA, created_at | `channel`, `client_id`, `client_name` | 개인정보 처리 시작 증거 |
| `auth.login` | Browser/Device/MCP 로그인 성공 | user_id, IP, UA, created_at | `channel`, `session_id`, `client_id`, `client_name`, `reused_session`, `signup` | 인증 성공 증거 |
| `auth.channel_mismatch` | auth_request 채널 불일치 차단 | user_id, IP, UA, created_at | `expected_channel`, `actual_channel`, `client_id`, `client_name` | 접근통제/오남용 차단 |
| `auth.resource_binding_failed` | MCP auth request resource binding 실패 | IP, UA, created_at | `client_id`, `client_name`, `reason` | resource binding 우회 차단 |
| `auth.access_denied` | 인증이 필요한 authgate 민감 작업 401 | IP, UA, created_at | `operation`, `status_code`, `reason` | 민감 작업 접근 거부 증거 |
| `auth.inactive_user` | disabled/pending_deletion/deleted 접근 차단 | user_id, IP, UA, created_at | `status`, `channel`, `phase` | 비활성 계정 차단 |
| `auth.device_code_issued` | device code 발급 | IP, UA, created_at | `client_id`, `client_name` | device flow 시작 증거 |
| `auth.device_approved` | device code 승인 | user_id, IP, UA, created_at | `client_id`, `client_name` | 사용자 승인 증거 |
| `auth.device_denied` | device code 거부 | user_id, IP, UA, created_at | `client_id`, `client_name` | 사용자 거부 증거 |
| `auth.token_refreshed` | refresh token rotation 성공 | user_id, IP, UA, created_at | `client_id`, `client_name`, `family_id` | token lifecycle 증거 |
| `auth.token_revoked` | RFC 7009 refresh token revoke | user_id, IP, UA, created_at | `client_id`, `client_name` | token 폐기 증거 |
| `auth.logout` | RP-Initiated Logout | user_id, IP, UA, created_at | `client_id`, `client_name` | 세션 종료 증거 |
| `auth.refresh_reuse_detected` | 폐기 refresh token 재사용 | user_id, created_at | `family_id` | token 탈취 의심 증거 |
| `auth.refresh_family_revoked` | reuse 감지 후 family revoke | user_id, created_at | `family_id` | 사고 완화 증거 |
| `auth.deletion_requested` | `DELETE /account` 성공 | user_id, IP, UA, created_at | `channel`, `session_id`, `client_id`, `client_name` | 삭제 요청 증거 |
| `auth.deletion_cancelled` | pending_deletion 브라우저 재로그인 복구 | user_id, IP, UA, created_at | `channel`, `session_id`, `client_id`, `client_name` | 삭제 취소 증거 |
| `auth.deletion_completed` | cleanup PII scrub 완료 | user_id, created_at | `reason` | 파기 완료 증거 |
| `auth.connection_revoked` | console connection revoke | user_id, IP, UA, created_at | `client_id`, `client_name` | 연결 폐기 증거 |
| `auth.session_revoked` | console session revoke | user_id, IP, UA, created_at | `session_id` | 세션 폐기 증거 |
| `auth.other_sessions_revoked` | 현재 세션 외 revoke | user_id, IP, UA, created_at | `current_session_id` | 세션 일괄 폐기 증거 |
| `console.clients_listed` | client 목록 조회 | user_id, IP, UA, created_at | `result_count` | 민감 조회 증거 |
| `console.connections_listed` | 연결 목록 조회 | user_id, IP, UA, created_at | `result_count` | 민감 조회 증거 |
| `console.sessions_listed` | 세션 목록 조회 | user_id, IP, UA, created_at | `result_count` | 민감 조회 증거 |
| `console.audit_log_viewed` | audit log 조회 | user_id, IP, UA, created_at | `page`, `limit`, `result_count` | 감사정보 조회 증거 |
| `console.access_denied` | console 401/403 | user_id(403만), IP, UA, created_at | `operation`, `status_code`, `reason`, `user_status` | 접근 거부 증거 |

## Endpoint Evidence Matrix

| Endpoint | 감사 기준 | Rate limit 기준 |
|----------|-----------|-----------------|
| `GET /login` | reused session login, channel mismatch, deletion cancel 경로 기록 | auth limiter |
| `GET /login/callback` | signup/login/inactive user 기록 | auth limiter |
| `GET /mcp/login` | inactive user, reused session login, channel mismatch 기록 | auth limiter |
| `GET /mcp/callback` | login/inactive user/resource binding 실패 기록 | auth limiter |
| `POST /oauth/token` | refresh success, reuse detection, family revoke 기록 | token limiter |
| `POST /oauth/revoke` | matching refresh token revoke 기록 | token limiter |
| `POST /oauth/device/authorize` | device code issued 기록 | token limiter |
| `GET /device` | page render 자체는 감사 이벤트 없음 | auth limiter |
| `GET /device/auth/callback` | device login/inactive user 기록 | auth limiter |
| `POST /device/approve` | approve/deny/inactive user 기록 | token limiter |
| `DELETE /account` | deletion requested/inactive user/access denied 기록 | auth limiter |
| `GET /console/clients` | clients listed/access denied 기록 | auth limiter |
| `GET /console/me/connections` | connections listed/access denied 기록 | auth limiter |
| `DELETE /console/me/connections/{client_id}` | connection revoked/access denied 기록 | auth limiter |
| `GET /console/me/sessions` | sessions listed/access denied 기록 | auth limiter |
| `DELETE /console/me/sessions/{id}` | session revoked/access denied 기록 | auth limiter |
| `POST /console/me/sessions/revoke-others` | other sessions revoked/access denied 기록 | auth limiter |
| `GET /console/me/audit-log` | audit log viewed/access denied 기록 | auth limiter |

## 서비스 기준과 통제 매핑

| 서비스 감사 기준 | 개인정보 보호법령/안전성 확보조치 | ISMS-P | SOC 2 |
|------------------|-----------------------------------|--------|-------|
| 접속기록 저장 | 접속기록 보관 및 점검 | 2.9 운영관리, 2.11 사고 예방 및 대응 | CC7 |
| append-only guard | 접속기록 위변조/도난/분실 방지 | 2.9 운영관리 | CC7 |
| metadata allowlist | 최소 수집, 오남용 방지 | 3.2 보유 및 이용 시 보호조치 | Privacy, Confidentiality |
| token reuse/family revoke event | 침해 의심 조사 증거 | 2.11 사고 예방 및 대응 | CC7 |
| console read/deny event | 접근통제 증거 | 2.5 인증 및 권한관리, 2.6 접근통제 | CC6 |
| deletion requested/completed event | 파기 증거 | 3.4 개인정보 파기 | Privacy |

## 완료 조건

새 감사 이벤트를 추가할 때는 다음을 모두 만족해야 한다.

1. `event_type` 이름이 고정되어 있다.
2. event별 metadata allowlist가 있다.
3. secret/token 원문을 metadata에 넣지 않는다.
4. 구현 위치와 테스트 위치가 명확하다.
5. endpoint 또는 service trigger가 이 문서에 추가된다.
6. 개인정보 처리 또는 보안 통제와의 연결이 설명된다.

## 공식 출처

| 출처 | 확인 내용 | 문서 기준 |
|------|-----------|-----------|
| [개인정보 보호법 제29조](https://www.law.go.kr/LSW/lsLawLinkInfo.do?chrClsCd=010202&lsJoLnkSeq=900079357) | 안전조치의무 | `[시행 2025.10.2] [법률 제20897호]` |
| [개인정보 보호법 제34조](https://law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1020398739) | 유출 등의 통지/신고 | `[시행 2025.10.2] [법률 제20897호]` |
| [개인정보 보호법 시행령 제30조](https://law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1025277153) | 개인정보의 안전성 확보 조치 | `[시행 2025.10.2] [대통령령 제35780호]` |
| [개인정보의 안전성 확보조치 기준 제8조](https://www.law.go.kr/LSW/admRulSideInfoP.do?admRulSeq=2100000265956&chrClsCd=010201&dashNo=&docCls=jo&joBrNo=00&joNo=0008&urlMode=admRulScJoRltInfoR) | 접속기록 보관/점검, 1년/2년 보존, 위변조 방지 | `[시행 2025.10.31] [개인정보보호위원회고시 제2025-9호]` |
| [KISA ISMS-P 제도소개](https://isms.kisa.or.kr/main/ispims/intro/) | 보호대책 및 개인정보 처리단계 요구사항 | 2026-05-26 확인 |
| [AICPA SOC Suite of Services](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2) | SOC 2 Trust Services Criteria 자료 | 2026-05-26 확인 |
