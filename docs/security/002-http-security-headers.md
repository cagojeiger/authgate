# HTTP 보안 응답 헤더

authgate는 모든 HTTP 응답에 기본 보안 헤더를 설정한다. 구현은
`internal/middleware/security_headers.go`의 `SecurityHeaders` 미들웨어이며,
미들웨어 체인의 **가장 바깥**(`internal/app/app.go`)에 배치되어 에러 응답과
CORS preflight 응답에도 헤더가 포함된다.

## 설정되는 헤더

| 헤더 | 값 | 목적 |
|------|-----|------|
| `X-Content-Type-Options` | `nosniff` | MIME 스니핑 차단 |
| `X-Frame-Options` | `DENY` | 클릭재킹 차단 (프레임 임베드 금지) |
| `Referrer-Policy` | `no-referrer` | URL의 code/token이 Referer로 유출되는 것 방지 |
| `Content-Security-Policy` | 아래 참조 | 스크립트 실행 전면 차단 + 리소스 출처 제한 + `frame-ancestors 'none'` |
| `Strict-Transport-Security` | `max-age=31536000` | HTTPS 강제. **`DEV_MODE=false`일 때만** 전송 |

## CSP 정책

```
default-src 'none';
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
font-src https://fonts.gstatic.com;
img-src 'self' data:;
frame-ancestors 'none';
base-uri 'none'
```

`internal/pages/templates/*.html`(device-entry, device-approve, result, error)는
인라인 `<style>` 하나와 Google Fonts만 사용하고 스크립트가 전혀 없다. 따라서
`default-src 'none'`로 스크립트 출처를 상속 차단(script-src 미지정 → 어떤 JS도
실행 불가)하면서, 필요한 스타일/폰트만 허용한다. JSON API 응답에도 동일 헤더가
붙지만 브라우저가 JSON 본문에서 하위 리소스를 로드하지 않으므로 무해하다.

## 비고

- HSTS는 dev 모드(평문 HTTP)에서 무의미하므로 생략한다. `includeSubDomains`는
  authgate가 제어하지 않는 형제 서브도메인에 HTTPS를 강제할 수 있어 기본값에서
  제외했다. 더 강한 정책은 프록시 계층에서 추가할 수 있다.
- 테스트: `internal/middleware/security_headers_test.go`
