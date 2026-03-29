# ADR-001: OAuth2/OIDC 구현에 zitadel/oidc v3 라이브러리 채택

## Status

Accepted (2026-03-28)

## Context

authgate는 OAuth2/OIDC 인증 게이트웨이로, 클라이언트에게는 OAuth2 서버 역할을 하면서 실제 인증은 upstream IdP(Google, Mock)에 위임하는 프록시 패턴을 사용한다.

초기 구현은 모든 OAuth2/OIDC 프로토콜을 직접 구현(hand-rolled)했다:
- Authorization Code + PKCE 플로우
- Device Flow (RFC 8628)
- JWT/JWKS 생성 및 서빙
- OIDC Discovery
- Refresh Token Rotation
- 토큰 엔드포인트

이 과정에서 다음 문제들이 발생했다:
- **보안 누락**: client_secret 검증 미구현, JWKS `e` 필드 인코딩 버그
- **상태 관리 결함**: in-memory map으로 auth request/device code 관리 → 메모리 누수, 재시작 시 유실
- **스펙 준수 불확실**: RFC 해석 실수로 인한 프로토콜 위반 가능성
- **유지보수 부담**: 2,774줄의 프로토콜 구현 코드를 직접 관리

## Decision

`github.com/zitadel/oidc/v3` 라이브러리를 채택하여 OAuth2/OIDC 프로토콜 계층을 위임한다.

authgate는 zitadel의 `op.Storage` 인터페이스(28개 메서드)를 PostgreSQL 기반으로 구현하고, 로그인 UI와 upstream IdP 연동만 직접 처리한다.

## Decision Drivers

1. **인증은 규약 기반**: OAuth2/OIDC는 RFC 6749, 7636, 8628 등 명확한 규약이 있으며, 직접 구현하면 규약 해석 오류가 보안 취약점으로 이어진다.
2. **검증된 정확성**: zitadel/oidc는 OpenID Foundation Basic OP 인증을 받았으며, ZITADEL 플랫폼의 프로덕션에서 매일 사용된다.
3. **코드 간결성**: 프로토콜 구현을 라이브러리에 위임하면 authgate는 비즈니스 로직(유저 관리, upstream 연동)에만 집중할 수 있다.

## Alternatives Considered

### 1. Hand-rolled 유지 + 버그 수정

- **장점**: 전체 코드 직접 제어, 외부 의존성 없음, 디버깅 용이
- **단점**: client auth, JWKS 버그, in-memory 누수 등 직접 수정 필요. RFC 업데이트마다 직접 반영. 2,774줄 유지보수.
- **기각 사유**: 이미 발견된 보안 누락이 3건 이상. 프로토콜 구현은 commodity이며 직접 소유할 가치가 낮음.

### 2. ory/fosite 채택

- **장점**: Ory Hydra(OpenID 인증)의 기반 프레임워크. 성숙한 생태계.
- **단점**: 15개월간 릴리즈 없음(마지막 v0.49.0, 2024-12). Go 1.22에 머물러 있음. Storage 인터페이스 34개 메서드(zitadel 대비 과대). Device Flow 미릴리즈.
- **기각 사유**: 유지보수 중단 징후. Device Flow 필수인 authgate에 부적합.

### 3. dex / casdoor (완성 서버)

- **장점**: 배포만 하면 동작. 대규모 커뮤니티.
- **단점**: 임베드 불가(독립 서버). authgate의 upstream 프록시 패턴과 구조적 불일치. 커스터마이징 제한.
- **기각 사유**: authgate는 라이브러리로 임베드 가능한 OP가 필요.

## Consequences

### Positive

- **코드 55% 감소**: 3,678줄(최초) → 1,661줄(현재)
- **보안 강화**: client 인증 자동 처리, PKCE 검증 자동, JWKS 스펙 준수
- **Device Flow DB 기반**: in-memory 누수 해결, 재시작 안전
- **OIDC 스펙 준수 보장**: OpenID 인증 라이브러리가 프로토콜 처리
- **유지보수 경감**: 프로토콜 변경은 라이브러리 업데이트로 대응

### Negative

- **HTTP 라우팅 위임**: zitadel이 `/.well-known/*`, `/oauth/*` 등의 라우팅 소유. chi router에서 커스텀 라우트를 먼저 등록하고 OP를 마지막에 마운트하는 패턴 필요.
- **Storage 인터페이스 학습**: 28개 메서드의 계약과 데이터 흐름 이해 필요.
- **디버깅 복잡성 증가**: 프로토콜 에러 발생 시 라이브러리 내부 추적 필요.

## Follow-ups

- [x] RSA 키를 파일에 저장하여 재시작 시 토큰 무효화 방지 → `loadOrGenerateKey("signing_key.pem")` 구현
- [x] `DevMode` config 기반으로 변경 → `DEV_MODE` 환경변수, 기본값 false
- [x] Consent 제거 — first-party 전용이므로 불필요. auto-approve로 대체
- [ ] Storage 통합 테스트 작성 (DB 연결 필요한 CRUD 메서드)
