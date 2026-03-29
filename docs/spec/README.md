# authgate 서비스 스펙

## 개요

authgate가 제공하는 전체 서비스 경험을 정의한다.
설계 원칙은 [ADR-000](../adr/000-authgate-identity.md), 기술 선택은 [ADR-001](../adr/001-adopt-zitadel-oidc.md)을 따른다.

## 목차

| # | 스펙 | 설명 | 대상 |
|---|------|------|------|
| 001 | [가입](001-signup.md) | Google 로그인 → 약관 동의 → 연령 확인 → 계정 생성 | 신규 사용자 |
| 002 | [브라우저 로그인](002-browser-login.md) | 웹 앱에서 Auth Code + PKCE로 토큰 발급 | 웹 앱 사용자 |
| 003 | [Device 로그인](003-device-login.md) | CLI에서 Device Code로 토큰 발급 | CLI 사용자 |
| 004 | [MCP 로그인](004-mcp-login.md) | AI 도구에서 OAuth 2.1로 토큰 발급 | AI 도구 (Claude, Cursor) |
| 005 | [토큰 Lifecycle](005-token-lifecycle.md) | 토큰 갱신, 검증, 폐기 | 앱 개발자 |
| 006 | [계정 Lifecycle](006-account-lifecycle.md) | 계정 상태 관리, 삭제, 복구 | 사용자 + 운영자 |

## 흐름

```
사용자 최초 접속
  │
  ▼
001 가입 (약관 + 연령 → 계정 생성)
  │
  ▼
002/003/004 로그인 (채널별 토큰 발급)
  │
  ▼
005 토큰 사용 (갱신, 검증, 폐기)
  │
  ▼
006 계정 관리 (상태 변경, 탈퇴)
```
