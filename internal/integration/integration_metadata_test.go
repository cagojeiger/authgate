//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"sort"
	"testing"
)

// #189 / RFC 8414 §2: discovery metadata MUST list the auth methods the AS
// actually accepts. zitadel/oidc's /oauth/token branch always accepts
// client_secret_basic (the OIDC default), and accepts client_secret_post
// when AuthMethodPost is true. Public clients use `none`. Authgate has
// AuthMethodPost=true, so all three are accepted — and must all be
// advertised so confidential clients trusting discovery don't pick the
// wrong credential location and silently fail.
//
// The same applies to /oauth/revoke per RFC 7009: AuthMethodsRevocationEndpoint
// in zitadel/oidc returns the same set, so a `revocation_endpoint_auth_methods_supported`
// entry must mirror it.
func TestIntegration_ASMetadata_AdvertisesAllAcceptedAuthMethods(t *testing.T) {
	ts := SetupTestServer(t)

	resp, err := http.Get(ts.BaseURL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("metadata request: %v", err)
	}
	defer resp.Body.Close()

	var metadata map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}

	expected := []string{"client_secret_basic", "client_secret_post", "none"}

	tokenMethods := stringSlice(t, metadata, "token_endpoint_auth_methods_supported")
	if !sortedEqual(tokenMethods, expected) {
		t.Errorf("token_endpoint_auth_methods_supported = %v, want %v", tokenMethods, expected)
	}

	revokeMethods := stringSlice(t, metadata, "revocation_endpoint_auth_methods_supported")
	if !sortedEqual(revokeMethods, expected) {
		t.Errorf("revocation_endpoint_auth_methods_supported = %v, want %v", revokeMethods, expected)
	}

	// /oauth/introspect is mounted by zitadel by default but only authenticates
	// confidential clients via Basic; the metadata MUST advertise the
	// endpoint and its narrower auth-method set so RFC 8414 §2 holds.
	if got, _ := metadata["introspection_endpoint"].(string); got == "" {
		t.Errorf("introspection_endpoint missing from metadata")
	}
	introspectMethods := stringSlice(t, metadata, "introspection_endpoint_auth_methods_supported")
	if !sortedEqual(introspectMethods, []string{"client_secret_basic"}) {
		t.Errorf("introspection_endpoint_auth_methods_supported = %v, want [client_secret_basic]", introspectMethods)
	}
}

func stringSlice(t *testing.T, metadata map[string]any, key string) []string {
	t.Helper()
	raw, ok := metadata[key]
	if !ok {
		t.Fatalf("metadata missing key %q", key)
	}
	arr, ok := raw.([]any)
	if !ok {
		t.Fatalf("metadata[%q] is %T, want []any", key, raw)
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("metadata[%q] entry is %T, want string", key, v)
		}
		out = append(out, s)
	}
	return out
}

func sortedEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
