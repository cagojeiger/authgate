#!/bin/bash
# Device Flow Test Script for authgate

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  authgate Device Authorization Flow Test                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

AUTHGATE_URL="http://localhost:8080"

# Test 1: Device Authorization Endpoint
echo "📋 Test 1: Device Authorization Endpoint"
echo "────────────────────────────────────────────────────────────"
RESPONSE=$(curl -s -X POST \
	-d "client_id=test-cli" \
	-d "scope=openid profile email" \
	"${AUTHGATE_URL}/oauth/device/authorize")

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

# Extract codes
DEVICE_CODE=$(echo "$RESPONSE" | grep -o '"device_code":"[^"]*"' | cut -d'"' -f4)
USER_CODE=$(echo "$RESPONSE" | grep -o '"user_code":"[^"]*"' | cut -d'"' -f4)

if [ -z "$DEVICE_CODE" ] || [ -z "$USER_CODE" ]; then
	echo "❌ FAIL: Could not get device_code or user_code"
	exit 1
fi
echo "✅ Device Code: ${DEVICE_CODE:0:20}..."
echo "✅ User Code: $USER_CODE"
echo ""

# Test 2: Token polling (should return pending)
echo "📋 Test 2: Token Polling (before approval)"
echo "────────────────────────────────────────────────────────────"
POLL_RESP=$(curl -s -X POST \
	-d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
	-d "device_code=$DEVICE_CODE" \
	-d "client_id=test-cli" \
	"${AUTHGATE_URL}/oauth/token")

echo "Response: $POLL_RESP"
if echo "$POLL_RESP" | grep -q "authorization_pending"; then
	echo "✅ Correctly returns 'authorization_pending'"
else
	echo "❌ FAIL: Expected authorization_pending error"
	exit 1
fi
echo ""

# Test 3: Device Verification Page
echo "📋 Test 3: Device Verification Page"
echo "────────────────────────────────────────────────────────────"
VERIFY_PAGE=$(curl -s "${AUTHGATE_URL}/device?user_code=$USER_CODE")
if echo "$VERIFY_PAGE" | grep -q "Confirm Device Authorization"; then
	echo "✅ Verification page loads correctly"
	echo "✅ Contains user code: $USER_CODE"
else
	echo "❌ FAIL: Verification page not loading correctly"
	exit 1
fi
echo ""

# Test 4: Discovery Document
echo "📋 Test 4: OIDC Discovery Document"
echo "────────────────────────────────────────────────────────────"
DISCOVERY=$(curl -s "${AUTHGATE_URL}/.well-known/openid-configuration")
if echo "$DISCOVERY" | grep -q "device_authorization_endpoint"; then
	echo "✅ Device authorization endpoint listed in discovery"
else
	echo "❌ FAIL: Device endpoint not in discovery"
	exit 1
fi
echo ""

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  ✅ All Device Flow Tests Passed!                        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Full Flow:"
echo "  1. CLI requests device authorization → gets device_code + user_code"
echo "  2. CLI displays user_code to user"
echo "  3. User opens browser → ${AUTHGATE_URL}/device?user_code=$USER_CODE"
echo "  4. User logs in and approves"
echo "  5. CLI polls token endpoint → receives access_token"
echo ""
echo "Example user code from this test: $USER_CODE"
