# Architecture 002: MCP 분리 리팩터링 계획

> 이 문서는 [001-component-boundaries.md](001-component-boundaries.md)의 목표 구조를 달성하기 위한 실행 계획이다.
> 리팩터링 완료 후 archive 또는 삭제한다.

## 현재 구현과의 차이

현재 코드는 기능적으로 동작하지만, 코어와 MCP 확장이 몇 군데에서 섞여 있다.

```text
cmd/authgate/main.go
  - core 조립
  - mcp 조립
  - metadata 응답
  - resource context 주입

internal/service/login.go
  - browser / mcp 공용 서비스 + channel 분기

internal/handler/login.go
  - /login, /mcp/login, /login/callback, /mcp/callback 혼합

internal/storage/storage_auth_tokens.go
  - 공통 auth/token 로직 + MCP resource 정책 결합

internal/storage/cimd.go
  - storage 패키지 안에 MCP 전용 client discovery 포함
```

이 결합 때문에 "코어"와 "채널 어댑터"의 경계가 문서와 코드 모두에서 흐려진다.

## 공통부를 기준으로 본 이동 계획

### 코어에 남길 것

```text
internal/service/access.go
internal/service/device.go
internal/service/account.go
internal/storage/storage.go
internal/storage/users.go
internal/storage/storage_oidc_device.go
internal/storage/clients.go
internal/storage/cleanup_runner.go
internal/upstream/*
```

### built-in / optional adapter 경계로 분리해야 하는 것

```text
internal/service/login.go
  -> browser built-in adapter용 흐름
  -> mcp optional adapter용 흐름 분리

internal/handler/login.go
  -> browser built-in adapter handler
  -> mcp optional adapter handler

internal/storage/cimd.go
  -> mcp optional adapter

internal/storage/storage_auth_tokens.go
  -> 공통 token/storage
  -> resource/client 정책 seam 도입 (Phase 1에서 실행, 아래 "op.Storage 분리 전략" 참조)

cmd/authgate/main.go
  -> core wiring
  -> built-in adapter wiring
  -> optional mcp wiring
```

## op.Storage 분리 전략 (필수 선행조건)

zitadel OP는 authgate의 service/handler가 아니라 `op.Storage`를 직접 호출한다.
따라서 MCP 정책 분리는 storage 경계에서 먼저 seam을 만들어야 한다.

```text
zitadel OP engine
  -> Storage.GetClientByClientID()
  -> Storage.AuthRequestByCode()
  -> Storage.TokenRequestByRefreshToken()
```

현재 MCP 결합이 들어 있는 핵심 지점:

```text
- CIMD fallback (GetClientByClientID)
- resource 일치/필수 검증 (AuthRequestByCode, TokenRequestByRefreshToken)
```

### 선택지

```text
방법 A: storage decorator/wrapper
  mcpStorage wraps coreStorage
  zitadel에는 wrapper를 주입

방법 B: policy 주입 (권장 기본안)
  coreStorage는 policy 인터페이스를 호출만 함
  MCP adapter가 policy 구현을 주입
```

권장안은 B를 기본으로 하고, 필요 시 A를 보완적으로 사용한다.

```text
권장 기본안
  - core storage는 MCP를 직접 모른다
  - client/resource 정책은 interface로 호출
  - MCP adapter가 구현을 제공
```

예시 seam:

```text
type ClientResolutionPolicy interface {
  ResolveClient(ctx, clientID) (ClientProfile, error)
}

type ResourceBindingPolicy interface {
  ValidateAuthorizeRequest(ctx, clientID, resource string) error
  ValidateTokenRequest(ctx, clientID, storedResource, requestResource string) error
}
```

이 seam이 생겨야 `CIMD/resource를 adapter/mcp로 이동`하는 Phase가 실행 가능해진다.

## 단계별 리팩터링 순서

```text
Phase 1
  - op.Storage seam 도입 (client/resource policy 추상화)
  - storage에서 MCP 로직을 분리할 수 있는 경계 확보

Phase 2
  - CIMD와 resource 정책을 MCP 어댑터 패키지로 이동
  - core storage에서 MCP 전용 책임 제거/축소

Phase 3
  - browser built-in adapter 와 mcp optional adapter 흐름 분리
  - /login 과 /mcp route/handler 분리

Phase 4
  - main 조립을 core + built-in adapters + optional mcp 형태로 변경
  - 문서와 코드의 패키지 매핑을 목표 구조 기준으로 갱신
```
