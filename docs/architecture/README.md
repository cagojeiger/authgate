# authgate 아키텍처 문서

## 개요

authgate의 내부 구조, 컴포넌트 경계, 의존 관계를 정의한다.
설계 원칙은 [ADR-000](../adr/000-authgate-identity.md), 기술 선택은 [ADR-001](../adr/001-adopt-zitadel-oidc.md)을 따른다.

## 문서 목록

| # | 문서 | 목적 |
|---|------|------|
| 001 | [컴포넌트 경계](001-component-boundaries.md) | authgate 내부 컴포넌트의 책임, 의존 방향, Go 패키지 매핑 |
| 002 | [MCP 분리 계획](002-mcp-separation-plan.md) | MCP를 optional adapter로 분리하는 리팩터링 실행 계획 (완료 후 삭제) |
