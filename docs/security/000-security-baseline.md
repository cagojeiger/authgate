# Security 000: 서비스 보안 설계 기준

검토일: 2026-05-26
상위 결정: [ADR-002: 서비스 보안 설계의 상위 참조 기준 채택](../adr/002-service-security-reference.md)

## 목적

이 문서는 SOC 2, ISMS-P, 개인정보 보호법령 및 개인정보의 안전성 확보조치
기준에서 authgate 서비스가 직접 적용할 수 있는 통제 목표만 선별해 서비스
보안 설계 기준으로 정의한다.

범위는 서비스 기능, 데이터 흐름, 접근통제, 감사로그, 설정 계약, 개인정보
처리 방식이다. 조직 운영, 인증 심사, 내부 감사, 상시 보안 운영 체계 전체는
다루지 않는다.

## 적용 원칙

| 원칙 | 의미 |
|------|------|
| 서비스가 강제할 수 있어야 한다 | 코드, DB 스키마, 설정 검증, 테스트로 확인 가능한 항목만 필수 기준으로 둔다. |
| 운영 증거와 분리한다 | 접근권한 정기 리뷰, 백업 복구 훈련, 인사/물리보안, 감사 대응은 이 문서의 구현 대상이 아니다. |
| 소비 앱 책임을 흡수하지 않는다 | 약관, 개인정보 동의, 앱별 권한, 비즈니스 정책은 authgate 밖에 둔다. |
| 법령 하한을 서비스 기본값으로 반영한다 | 접속기록 보존, 위변조 방지, 암호화, 접근통제는 서비스 기본 계약에 포함한다. |
| SOC 2/ISMS-P는 통제 언어로 사용한다 | 보고서나 인증서가 아니라 서비스 설계와 증거 생성 기준으로만 사용한다. |

## 서비스 범위

authgate가 직접 보호해야 하는 자산은 다음이다.

| 자산 | 보안 기준 |
|------|-----------|
| OAuth/OIDC 인증 흐름 | authorization code, device code, MCP login 흐름은 채널과 client/resource binding을 검증해야 한다. |
| 사용자 신원 데이터 | email, name, avatar_url, IdP subject는 최소 수집/보유/삭제 기준을 따라야 한다. |
| 세션 | 세션 쿠키는 production에서 Secure 속성을 강제하고 TTL/revoke 계약을 가져야 한다. |
| refresh token | 원문 저장 금지, hash 저장, rotation, reuse detection, family revoke가 필요하다. |
| signing key/session secret/client secret | 빌드 산출물에 포함하지 않고, 서비스는 안전한 경로와 최소 길이/해시 계약을 강제해야 한다. |
| audit log | 보안 이벤트는 조사 가능한 형태로 저장하고, metadata는 allowlist로 제한해야 한다. |
| client metadata | YAML client와 CIMD client는 허용 redirect/grant/channel/resource 계약을 검증해야 한다. |
| 설정 | production guard, timeout, rate limit, trusted proxy, issuer allowlist 등은 명시적 계약을 가져야 한다. |

authgate가 직접 맡지 않는 영역은 다음이다.

| 제외 영역 | 이유 |
|-----------|------|
| 약관/개인정보 동의 | authgate는 순수 인증 서비스이며 동의 UX를 제공하지 않는다. |
| 개인정보 처리방침 게시와 정보주체 민원 처리 | 서비스 밖 운영/법무 책임이다. |
| 앱별 RBAC/ABAC/조직 권한 | ADR-000에 따라 authgate는 권한 시스템이 아니다. |
| 운영자 DB/클라우드 계정 권한관리 | 서비스 코드가 직접 검증할 수 없는 조직 운영 통제다. |
| 물리보안, 인사보안, 공급망 심사, 백업 복구 훈련 | ISMS-P/SOC 2 운영 증거이며 서비스 기능이 아니다. |
| SOC 2 보고서, ISMS-P 인증서 | 독립 감사/인증 절차의 산출물이다. |

## 기준 적용 결론

| 기준 | 서비스 적용 방식 | 기준일/유효성 |
|------|------------------|---------------|
| 개인정보 보호법령 및 안전성 확보조치 기준 | 접근통제, 암호화, 접속기록, 위변조 방지, 파기, 침해 조사 증거를 서비스 기능으로 반영한다. | 개인정보 보호법 `[시행 2025.10.2]`, 시행령 제30조 `[시행 2025.10.2]`, 안전성 확보조치 기준 `[시행 2025.10.31] [개인정보보호위원회고시 제2025-9호]` 기준. |
| ISMS-P | 인증 전체가 아니라 보호대책 요구사항과 개인정보 처리단계 요구사항 중 서비스가 구현 가능한 항목만 적용한다. | KISA 공개 기준을 2026-05-26 확인. 인증 유효기간/사후심사는 운영 범위 밖이다. |
| SOC 2 | Security를 기본 통제 언어로 사용하고, Confidentiality/Privacy/Availability/Processing Integrity 중 서비스 기능에 해당하는 항목만 매핑한다. | AICPA 2017 TSC with Revised Points of Focus - 2022, AICPA SOC 2 Guide 2022-10-15 업데이트 기준. 보고서 유효성은 서비스 범위 밖이다. |

## 서비스 보안 기준

| ID | 기준 | 구현/증거 위치 |
|----|------|----------------|
| AG-SVC-SEC-001 | production에서는 HTTPS public URL과 HTTPS upstream issuer를 강제한다. | `internal/config/config.go`, `docs/spec/009-operations.md` |
| AG-SVC-SEC-002 | `SESSION_SECRET`은 production에서 32자 이상이어야 한다. | `internal/config/config.go` |
| AG-SVC-SEC-003 | OIDC issuer allowlist를 제공하고 설정 시 issuer host 불일치를 fail-fast 한다. | `internal/config/config.go`, `docs/spec/009-operations.md` |
| AG-SVC-SEC-004 | trusted proxy가 설정되지 않으면 proxy header를 신뢰하지 않는다. | `internal/clientinfo/*`, `docs/spec/009-operations.md` |
| AG-SVC-SEC-005 | 인증/토큰/console 계열 endpoint에는 rate limit 계약을 둔다. | `internal/middleware/ratelimit.go`, `internal/app/routes.go` |
| AG-SVC-SEC-006 | HTTP server timeout과 graceful shutdown timeout을 설정으로 제공한다. | `internal/config/config.go`, `internal/app/server.go` |
| AG-SVC-SEC-007 | refresh token은 원문 저장 금지, SHA-256 hash 저장, rotation을 유지한다. | `docs/spec/005-token-lifecycle.md`, `internal/storage/storage_auth_tokens.go` |
| AG-SVC-SEC-008 | refresh token reuse가 감지되면 token family를 revoke하고 audit event를 남긴다. | `internal/storage/storage_auth_tokens.go`, `docs/security/001-audit-evidence-matrix.md` |
| AG-SVC-SEC-009 | access token은 DB에 저장하지 않고 짧은 TTL을 기본값으로 둔다. | `docs/spec/005-token-lifecycle.md`, `README.md` |
| AG-SVC-SEC-010 | client secret은 bcrypt hash로만 등록한다. | `docs/spec/009-operations.md`, `internal/storage/bcrypt.go` |
| AG-SVC-SEC-011 | signing key와 secret 파일은 빌드 산출물에 포함하지 않는 계약을 유지한다. | `.dockerignore`, `docs/spec/009-operations.md` |
| AG-SVC-SEC-012 | browser/device/MCP channel mismatch는 거부하고 audit event를 남긴다. | `internal/service/login.go`, `docs/security/001-audit-evidence-matrix.md` |
| AG-SVC-SEC-013 | MCP auth request는 resource binding을 검증한다. | `internal/service/mcp_login.go`, `docs/spec/004-mcp-login.md` |
| AG-SVC-SEC-014 | 계정 삭제 요청 시 refresh token을 revoke하고 30일 유예 후 PII scrub을 수행한다. | `docs/spec/006-account-lifecycle.md`, `internal/storage/cleanup_runner.go` |
| AG-SVC-SEC-015 | deleted user는 재활성화하지 않고 재가입은 새 user로 분리한다. | `docs/spec/006-account-lifecycle.md`, `docs/adr/000-authgate-identity.md` |
| AG-SVC-SEC-016 | audit metadata는 event별 allowlist만 저장하고 secret/token 원문은 저장하지 않는다. | `internal/storage/audit.go` |
| AG-SVC-SEC-017 | audit log 핵심 필드는 append-only로 유지하고 PII redaction만 허용한다. | `migrations/003_audit_log_immutability.up.sql` |
| AG-SVC-SEC-018 | audit PII 보존기간은 최소 365일, 기본 1095일로 설정한다. | `internal/config/config.go`, `README.md` |
| AG-SVC-SEC-019 | 5만명 이상 정보주체, 민감정보/고유식별정보 처리 등 2년 보존 조건에 대비해 730일 이상 설정 가능해야 한다. | `internal/config/config.go` |
| AG-SVC-SEC-020 | audit write 실패는 business flow를 깨지 않되 오류 로그로 드러나야 한다. | `internal/storage/audit.go`, `docs/spec/009-operations.md` |
| AG-SVC-SEC-021 | `/health`와 `/ready`는 liveness/readiness를 분리한다. | `internal/app/routes.go`, `docs/spec/006-account-lifecycle.md` |
| AG-SVC-SEC-022 | `/account`, `/console/*`, token revoke/session revoke 등 민감 작업은 인증과 audit를 요구한다. | `internal/service/account.go`, `internal/service/console.go` |
| AG-SVC-SEC-023 | 보안 계약은 테스트로 회귀를 막는다. | `internal/config/*_test.go`, `internal/storage/*audit*_test.go`, `internal/integration/*_test.go` |

## 기준 매핑

| 서비스 기준 | 개인정보 보호법령/안전성 확보조치 | ISMS-P | SOC 2 |
|-------------|-----------------------------------|--------|-------|
| production HTTPS, secure cookie, timeout, rate limit | 접근통제, 안전성 확보 조치 | 2.6 접근통제, 2.10 시스템 및 서비스 보안관리 | CC6, CC7 |
| token hash, client secret hash, signing key 계약 | 암호화, 인증정보 보호 | 2.5 인증 및 권한관리, 2.7 암호화 적용 | CC6, Confidentiality |
| audit event, retention, append-only guard | 접속기록 보관/점검/위변조 방지 | 2.9 시스템 운영관리, 2.11 사고 예방 및 대응 | CC7 |
| account deletion, PII scrub, audit PII redaction | 파기, 개인정보 처리단계 보호 | 3.2 보유 및 이용, 3.4 파기 | Privacy |
| channel/resource/client binding | 접근통제, 오남용 방지 | 2.5 인증 및 권한관리, 2.6 접근통제 | CC6, Processing Integrity |
| health/readiness, graceful shutdown | 직접 법령 하한은 아님 | 2.12 재해복구 일부, 2.9 운영관리 일부 | Availability |

## 공식 출처

| 출처 | 확인 내용 | 문서 기준 |
|------|-----------|-----------|
| [AICPA SOC Suite of Services](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2) | SOC 2 Guide, 2017 TSC with Revised Points of Focus - 2022, SOC 2 Description Criteria | 2026-05-26 확인 |
| [AICPA 2017 Trust Services Criteria with Revised Points of Focus - 2022](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022?Jid=CppDev20110217) | Security, Availability, Processing Integrity, Confidentiality, Privacy 기준 | 리소스 게시일 2023-09-30 |
| [KISA ISMS-P 제도소개](https://isms.kisa.or.kr/main/ispims/intro/) | ISMS-P 인증기준: 관리체계, 보호대책, 개인정보 처리단계 요구사항 | 2026-05-26 확인 |
| [KISA ISMS-P 인증대상](https://isms.kisa.or.kr/main/ispims/target/) | 의무대상 기준 | 2026-05-26 확인 |
| [개인정보 보호법 제29조](https://www.law.go.kr/LSW/lsLawLinkInfo.do?chrClsCd=010202&lsJoLnkSeq=900079357) | 안전조치의무 | `[시행 2025.10.2] [법률 제20897호]` |
| [개인정보 보호법 제34조](https://law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1020398739) | 유출 등의 통지/신고 | `[시행 2025.10.2] [법률 제20897호]` |
| [개인정보 보호법 시행령 제30조](https://law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1025277153) | 개인정보의 안전성 확보 조치 | `[시행 2025.10.2] [대통령령 제35780호]` |
| [개인정보의 안전성 확보조치 기준 제5조](https://www.law.go.kr/LSW/admRulSideInfoP.do?admRulSeq=2100000265956&chrClsCd=010201&dashNo=&docCls=jo&joBrNo=00&joNo=0005&urlMode=admRulScJoRltInfoR) | 접근 권한의 관리 | `[시행 2025.10.31] [개인정보보호위원회고시 제2025-9호]` |
| [개인정보의 안전성 확보조치 기준 제6조](https://www.law.go.kr/LSW/admRulSideInfoP.do?admRulSeq=2100000265956&chrClsCd=010201&dashNo=&docCls=jo&joBrNo=00&joNo=0006&urlMode=admRulScJoRltInfoR) | 접근통제 | `[시행 2025.10.31] [개인정보보호위원회고시 제2025-9호]` |
| [개인정보의 안전성 확보조치 기준 제7조](https://www.law.go.kr/LSW/admRulSideInfoP.do?admRulSeq=2100000265956&chrClsCd=010201&dashNo=&docCls=jo&joBrNo=00&joNo=0007&urlMode=admRulScJoRltInfoR) | 개인정보의 암호화 | `[시행 2025.10.31] [개인정보보호위원회고시 제2025-9호]` |
| [개인정보의 안전성 확보조치 기준 제8조](https://www.law.go.kr/LSW/admRulSideInfoP.do?admRulSeq=2100000265956&chrClsCd=010201&dashNo=&docCls=jo&joBrNo=00&joNo=0008&urlMode=admRulScJoRltInfoR) | 접속기록 보관/점검, 1년/2년 보존, 위변조 방지 | `[시행 2025.10.31] [개인정보보호위원회고시 제2025-9호]` |

## 재검토 트리거

| 트리거 | 해야 할 일 |
|--------|------------|
| 개인정보 보호법/시행령/안전성 확보조치 기준 개정 | 서비스 기준과 보존/감사 계약 재검토 |
| ISMS-P 또는 SOC 2 고객 요구 발생 | 서비스 기준과 운영 조직 기준을 분리해 별도 준비 문서 작성 |
| authgate가 동의/약관/권한관리/관리자 기능을 직접 제공하기 시작 | ADR-000, ADR-002, 이 문서 재검토 |
| 고유식별정보/민감정보 처리 추가 | 암호화, 접근통제, 접속기록 2년 보존, 영향평가 여부 재검토 |
