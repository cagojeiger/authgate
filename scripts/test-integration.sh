#!/bin/bash

echo "=== authgate 통합 테스트 ==="

BASE_URL="http://localhost:8080"
DB_URL="postgres://authgate:authgate@localhost:5432/authgate?sslmode=disable"
PASS=0
FAIL=0

check() {
  local name=$1
  if [ "$2" = "0" ]; then
    echo "  PASS: $name"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $name"
    FAIL=$((FAIL + 1))
  fi
}

# --- DB 스키마 검증 ---
echo ""
echo "[DB] 스키마 검증"

TABLES=$(psql "$DB_URL" -t -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('users','user_identities','sessions','refresh_tokens','oauth_clients','auth_requests','device_codes','audit_log')" 2>/dev/null | tr -d ' ')
test "$TABLES" = "8"; check "8개 테이블 존재" $?

# CHECK 제약조건 (실패를 기대)
psql "$DB_URL" -c "INSERT INTO users (email, status) VALUES ('check-fail-$(date +%s)@test.com', 'invalid')" > /dev/null 2>&1
test $? -ne 0; check "users.status CHECK 동작" $?

# device_codes state CHECK
psql "$DB_URL" -c "INSERT INTO device_codes (device_code, user_code, client_id, state, expires_at) VALUES ('dc-$(date +%s)','uc-$(date +%s)','c','bad_state', NOW())" > /dev/null 2>&1
test $? -ne 0; check "device_codes.state CHECK 동작" $?

# UNIQUE
psql "$DB_URL" -c "DELETE FROM users WHERE email='unique-integ@test.com'" > /dev/null 2>&1
psql "$DB_URL" -c "INSERT INTO users (email, status) VALUES ('unique-integ@test.com', 'active')" > /dev/null 2>&1
psql "$DB_URL" -c "INSERT INTO users (email, status) VALUES ('unique-integ@test.com', 'active')" > /dev/null 2>&1
test $? -ne 0; check "users.email UNIQUE 동작" $?

# CASCADE
USER_ID=$(psql "$DB_URL" -t -c "SELECT id FROM users WHERE email='unique-integ@test.com'" 2>/dev/null | tr -d ' ')
psql "$DB_URL" -c "INSERT INTO user_identities (user_id, provider, provider_user_id) VALUES ('$USER_ID', 'google', 'cascade-integ')" > /dev/null 2>&1
psql "$DB_URL" -c "DELETE FROM users WHERE id='$USER_ID'" > /dev/null 2>&1
REMAINING=$(psql "$DB_URL" -t -c "SELECT count(*) FROM user_identities WHERE provider_user_id='cascade-integ'" 2>/dev/null | tr -d ' ')
test "$REMAINING" = "0"; check "FK CASCADE 동작" $?

# --- OIDC 엔드포인트 검증 ---
echo ""
echo "[OIDC] 엔드포인트 검증"

DISCOVERY=$(curl -sf "$BASE_URL/.well-known/openid-configuration" 2>/dev/null || echo "")
test -n "$DISCOVERY"; check "Discovery 응답" $?

if [ -n "$DISCOVERY" ]; then
  ISSUER=$(echo "$DISCOVERY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('issuer',''))" 2>/dev/null)
  test "$ISSUER" = "$BASE_URL"; check "issuer=$BASE_URL" $?

  TOKEN_EP=$(echo "$DISCOVERY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token_endpoint',''))" 2>/dev/null)
  echo "$TOKEN_EP" | grep -q "oauth/token"; check "token_endpoint 포함 oauth/token" $?

  DEVICE_EP=$(echo "$DISCOVERY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('device_authorization_endpoint',''))" 2>/dev/null)
  echo "$DEVICE_EP" | grep -q "device"; check "device_authorization_endpoint 존재" $?
fi

# JWKS
JWKS_URI=$(echo "$DISCOVERY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('jwks_uri',''))" 2>/dev/null)
JWKS=$(curl -sf "$JWKS_URI" 2>/dev/null || echo "")
if [ -n "$JWKS" ]; then
  KEY_COUNT=$(echo "$JWKS" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('keys',[])))" 2>/dev/null)
  test "$KEY_COUNT" -ge 1 2>/dev/null; check "JWKS 키 ${KEY_COUNT}개" $?
else
  check "JWKS 응답" 1
fi

# Health
HEALTH=$(curl -sf "$BASE_URL/health" 2>/dev/null || echo "")
echo "$HEALTH" | grep -q "healthy"; check "/health" $?

READY=$(curl -sf "$BASE_URL/ready" 2>/dev/null || echo "")
echo "$READY" | grep -q "ready"; check "/ready" $?

# --- authorize 요청 ---
echo ""
echo "[Auth] authorize 요청 검증"

psql "$DB_URL" -c "
INSERT INTO oauth_clients (client_id, client_type, name, redirect_uris, allowed_scopes, allowed_grant_types)
VALUES ('test-app', 'public', 'Test App', '{http://localhost:9090/callback}', '{openid,profile,email,offline_access}', '{authorization_code,refresh_token}')
ON CONFLICT (client_id) DO NOTHING;
" > /dev/null 2>&1
check "테스트 클라이언트 등록" $?

AUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/authorize?client_id=test-app&redirect_uri=http://localhost:9090/callback&response_type=code&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=test" 2>/dev/null)
# 302 = redirect to login (expected), 200 = rendered page
test "$AUTH_CODE" = "302" -o "$AUTH_CODE" = "200"; check "authorize 요청 ($AUTH_CODE)" $?

# --- 결과 ---
echo ""
echo "================================"
echo "  PASS: $PASS / FAIL: $FAIL"
echo "================================"

test "$FAIL" = "0"
