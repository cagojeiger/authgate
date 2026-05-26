# ADR-001: OAuth2/OIDC 구현에 zitadel/oidc v3 라이브러리 채택
## Status
Accepted (2026-03-28)
## Context
ADR-000에서 authgate의 정체성을 "인증 경계이자 토큰 발급기"로 정의했다. 이 ADR은 그 정체성을 구현하기 위한 **기술 선택**을 다룬다.
authgate는 OIDC 인증 게이트웨이로, 클라이언트에게는 OAuth2 서버 역할을 하면서 실제 인증은 upstream IdP에 위임하는 프록시 패턴을 사용한다.
OAuth2/OIDC 프로토콜은 RFC 6749, 7636, 8628 등 명확한 규약이 있으며, 직접 구현하면 규약 해석 오류가 보안 취약점으로 이어진다. 프로토콜 계층은 검증된 라이브러리에 위임하고, authgate는 비즈니스 로직에만 집중한다.
## Decision
`github.com/zitadel/oidc/v3` 라이브러리를 채택한다.
### 라이브러리가 처리하는 것
| 영역 | 내용 |
|------|------|
| OAuth2/OIDC 프로토콜 전반 | authorize, token, JWKS, OIDC Discovery, Device Flow, Refresh rotation |
### authgate가 직접 처리하는 것
| 영역 | 내용 |
|------|------|
| authgate 책임 | DB 어댑터 구현, upstream IdP 코드 교환 + 사용자 정보 취득, 로그인 UI / 세션 관리 / 계정 lifecycle, auth request 완료 처리, 상태 기반 정책 적용 |
### 왜 zitadel/oidc인가
| 기준 | zitadel/oidc v3 |
|------|----------------|
| OpenID 표준성 | RP basic/config profile 인증 명시, OP 구현 제공 |
| 프로덕션 사용성 | ZITADEL 생태계에서 실제 사용되는 라이브러리 |
| Device Flow | 공식 지원 (RFC 8628) |
| 유지보수 | 월간 릴리즈, Go 최신 버전 지원 |
| 임베드 가능 | OP를 앱에 직접 내장할 수 있고 저장소 경계가 명확 |
### 기각한 대안
| 대안 | 기각 사유 |
|------|----------|
| ory/fosite | 임베드 라이브러리로 쓸 때 학습/구성 부담이 크고, 우리 구조에는 과함 |
| dex / casdoor | 독립 서버라 임베드 불가. upstream 프록시 패턴과 불일치 |
## Consequences
### Positive
- 프로토콜 정확성이 라이브러리에 의해 보장됨
- authgate 코드가 비즈니스 로직에만 집중
- 보안 필수 기능이 라이브러리에서 처리됨
- RFC 업데이트는 라이브러리 버전 업으로 대응
### Negative
- zitadel이 대부분의 프로토콜 라우팅을 소유
- 라이브러리 저장소 경계와 호출 흐름 학습 필요
- 프로토콜 에러 시 라이브러리 내부 추적 필요
