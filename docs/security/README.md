# authgate 보안/컴플라이언스 문서

## 개요

이 디렉토리는 authgate 서버가 코드와 설정으로 제공할 수 있는 보안 통제와
증거(evidence)를 추적한다.

authgate 밖의 조직 운영 절차(법무 판단, 고객 통지, 접근권한 정기 리뷰,
백업 복구 훈련, SOC 2 감사 대응)는 이 문서의 범위가 아니다. 다만 서버가
그 절차에 제공할 수 있는 로그, 이벤트, 설정, 테스트 위치를 명확히 연결한다.

## 문서 목록

| # | 문서 | 목적 |
|---|------|------|
| 001 | [Audit Evidence Matrix](001-audit-evidence-matrix.md) | 한국 PIPA/통비법/SOC 2 관점에서 authgate가 생성하는 감사 증거와 현재 구현 상태 매핑 |
| 002 | [HTTP 보안 응답 헤더](002-http-security-headers.md) | 모든 응답에 설정되는 보안 헤더(CSP, X-Frame-Options, HSTS 등)와 정책 근거 |

## 관계

```text
법/감사 요구
  │
  ▼
docs/security/*
  │  "서버가 어떤 증거를 제공하는가"
  │
  ├── docs/spec/*
  │     "서비스가 어떻게 동작해야 하는가"
  │
  ├── docs/tests/*
  │     "무엇을 테스트해야 하는가"
  │
  └── internal/*
        "실제 구현"
```
