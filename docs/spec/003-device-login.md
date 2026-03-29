# Spec 002: Device 로그인 (RFC 8628 Device Authorization Grant)

## 개요

CLI 도구나 입력 제한 장치에서 브라우저를 통해 인증하고 access_token + refresh_token을 받는 플로우.

## 전제 조건

- 앱이 `oauth_clients` 테이블에 등록 (grant_type에 device_code 포함)
- 사용자가 브라우저 접근 가능해야 함
- authgate에 유효한 세션이 있거나, Google 로그인 가능해야 함

## 표준

- RFC 8628 (OAuth 2.0 Device Authorization Grant)
- 5분 만료, 5초 polling 간격

## 플로우

```mermaid
sequenceDiagram
    participant CLI as CLI 앱
    participant AG as authgate
    participant Z as zitadel OP
    participant U as 사용자 브라우저

    Note over CLI,U: 1. Device Code 발급
    CLI->>Z: POST /oauth/device/authorize (client_id, scope)
    Z->>Z: StoreDeviceAuthorization (DB 저장)
    Z->>Z: device_code + user_code 생성
    Z-->>CLI: {device_code, user_code, verification_uri, expires_in, interval}

    Note over CLI,U: 2. CLI가 사용자에게 안내
    CLI->>CLI: 화면 출력
    Note right of CLI: "브라우저에서 열어주세요:<br/>https://auth.example.com/device<br/><br/>코드: BCDF-GHKM"

    Note over CLI,U: 3. 사용자가 브라우저에서 코드 입력
    U->>AG: GET /device
    AG-->>U: device_entry.html (코드 입력 폼)
    U->>AG: GET /device?user_code=BCDF-GHKM
    AG-->>U: device_approve.html (승인/거부 버튼)

    Note over CLI,U: 4. 사용자 승인
    alt 세션 있음
        U->>AG: POST /device/approve (user_code, action=approve)
        AG->>AG: getSessionUser → 유저 확인
        AG->>AG: CompleteDeviceAuthorization(userCode, userID)
        AG->>AG: audit: auth.device_approved
        AG-->>U: success.html "승인 완료"
    else 세션 없음
        AG-->>U: 401 "Login required"
        Note right of U: 사용자는 먼저<br/>웹에서 로그인해야 함
    end

    Note over CLI,U: 5. CLI Polling
    loop 5초마다 polling
        CLI->>Z: POST /oauth/token (grant_type=device_code, device_code=...)
        Z->>Z: GetDeviceAuthorizatonState(deviceCode)
        alt 아직 승인 안 됨
            Z-->>CLI: 400 {error: "authorization_pending"}
        else 사용자가 거부
            Z-->>CLI: 400 {error: "access_denied"}
        else 만료됨
            Z-->>CLI: 400 {error: "expired_token"}
        end
    end

    Note over CLI,U: 6. 승인 완료 → 토큰 발급
    CLI->>Z: POST /oauth/token (grant_type=device_code, device_code=...)
    Z->>Z: GetDeviceAuthorizatonState → Done=true
    Z->>Z: JWT 서명 (RSA)
    Z-->>CLI: {access_token, refresh_token, id_token}

    Note over CLI,U: ✅ CLI 로그인 완료
    CLI->>CLI: 토큰 저장 (~/.config/myapp/token.json)
```

## 상태 전이

```mermaid
stateDiagram-v2
    [*] --> pending: POST /device/authorize
    pending --> approved: 사용자가 Allow 클릭
    pending --> denied: 사용자가 Deny 클릭
    pending --> expired: expires_at 초과
    approved --> [*]: 토큰 발급 완료
    denied --> [*]: 에러 반환
    expired --> [*]: 에러 반환
```

## DB 테이블

```sql
device_codes (
    device_code  TEXT UNIQUE,   -- CLI에게 전달
    user_code    TEXT UNIQUE,   -- 사용자가 입력 (BCDF-GHKM)
    client_id    TEXT,
    scopes       TEXT[],
    state        TEXT,          -- pending / approved / denied
    subject      TEXT,          -- 승인 시 user_id 설정
    expires_at   TIMESTAMPTZ,  -- 5분
    auth_time    TIMESTAMPTZ   -- 승인 시각
)
```

## 에러 케이스

| 상황 | CLI에게 | HTTP |
|------|--------|------|
| 아직 승인 안 됨 | `authorization_pending` | 400 |
| 사용자가 거부 | `access_denied` | 400 |
| device_code 만료 | `expired_token` | 400 |
| polling 너무 빠름 | `slow_down` | 400 |
| 잘못된 user_code | error 페이지 | 200 (HTML) |
| 세션 없이 승인 시도 | `unauthorized` | 401 |

## 보안 요구사항

- user_code: 대문자만, 모호한 문자 제외 (0/O, 1/I 등)
- device_code: 충분한 엔트로피 (base20, 8자)
- 만료된 device_code는 승인 불가 (WHERE expires_at > NOW())
- polling 간격 5초 강제 (zitadel이 처리)
