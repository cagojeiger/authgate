// Package shared provides mock IdP handlers and OAuth helpers for all demo binaries.
// Temporary code — no authgate internal imports.
package shared

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// ============================================================
// Mock IdP Handlers
// ============================================================

type MockUser struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	EV    bool   `json:"email_verified"`
	Name  string `json:"name"`
	Pic   string `json:"picture,omitempty"`
}

func ScenarioUser(s string) *MockUser {
	switch s {
	case "new":
		return &MockUser{"new-sub-001", "new@example.com", true, "New User", ""}
	case "existing":
		return &MockUser{"existing-sub-001", "existing@example.com", true, "Existing User", ""}
	case "conflict":
		return &MockUser{"conflict-sub-999", "existing@example.com", true, "Conflict User", ""}
	default:
		return &MockUser{"mock-sub-default", "mock@example.com", true, "Mock User", "https://example.com/avatar.png"}
	}
}

func ParseScenario(code string) string {
	if !strings.HasPrefix(code, "mock-code-") {
		return "default"
	}
	parts := strings.SplitN(strings.TrimPrefix(code, "mock-code-"), "-", 2)
	if len(parts) == 0 {
		return "default"
	}
	return parts[0]
}

func MockDiscoveryHandler(publicURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": publicURL, "authorization_endpoint": publicURL + "/authorize",
			"token_endpoint": publicURL + "/token", "userinfo_endpoint": publicURL + "/userinfo",
			"jwks_uri": publicURL + "/keys", "scopes_supported": []string{"openid", "email", "profile"},
			"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"},
		})
	}
}

func MockAuthorize(w http.ResponseWriter, r *http.Request) {
	ru, state := r.URL.Query().Get("redirect_uri"), r.URL.Query().Get("state")
	if ru == "" || state == "" {
		http.Error(w, "missing redirect_uri or state", 400)
		return
	}
	sc := r.URL.Query().Get("mock_scenario")
	if sc == "" {
		sc = "default"
	}
	if sc == "denied" {
		http.Redirect(w, r, ru+"?error=access_denied&state="+state, 302)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("%s?code=mock-code-%s-%s&state=%s", ru, sc, state, state), 302)
}

func MockToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	r.ParseForm()
	code := r.FormValue("code")
	if code == "" {
		JSONErr(w, 400, "invalid_grant")
		return
	}
	sc := ParseScenario(code)
	if sc == "error" {
		JSONErr(w, 500, "server_error")
		return
	}
	if sc == "invalid" {
		JSONErr(w, 400, "invalid_grant")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": "mock-access-" + code, "token_type": "Bearer", "expires_in": 3600,
	})
}

func MockUserinfo(w http.ResponseWriter, r *http.Request) {
	var code string
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer mock-access-") {
		code = strings.TrimPrefix(a, "Bearer mock-access-")
	} else {
		code = r.URL.Query().Get("code")
	}
	if code == "" {
		http.Error(w, "unauthorized", 401)
		return
	}
	sc := ParseScenario(code)
	if sc == "userinfo_error" {
		JSONErr(w, 500, "server_error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ScenarioUser(sc))
}

// ============================================================
// OAuth Helpers
// ============================================================

func ExchangeCode(baseURL, code, clientID, redirectURI, verifier string) (map[string]any, error) {
	return PostToken(baseURL, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirectURI}, "client_id": {clientID}, "code_verifier": {verifier},
	})
}

func RefreshToken(baseURL, rt, clientID string) (map[string]any, error) {
	return PostToken(baseURL, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt},
		"client_id": {clientID}, "scope": {"openid profile email offline_access"},
	})
}

func PostToken(baseURL string, data url.Values) (map[string]any, error) {
	resp, err := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(body, &result)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("(%d) %s", resp.StatusCode, body)
	}
	return result, nil
}

func DeviceAuthorize(baseURL, clientID string) (map[string]any, error) {
	resp, err := http.Post(baseURL+"/oauth/device/authorize", "application/x-www-form-urlencoded",
		strings.NewReader(url.Values{"client_id": {clientID}, "scope": {"openid profile email offline_access"}}.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func DevicePoll(baseURL, deviceCode, clientID string) ([]byte, int) {
	data := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode}, "client_id": {clientID},
	}
	resp, err := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return []byte(`{"error":"` + err.Error() + `"}`), 500
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode
}

func GetUserinfo(baseURL, at string) map[string]any {
	req, _ := http.NewRequest("GET", baseURL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	defer resp.Body.Close()
	var info map[string]any
	json.NewDecoder(resp.Body).Decode(&info)
	return info
}

// ============================================================
// Utilities
// ============================================================

func RandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func S256(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func Pretty(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }

func EnvOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func JSONErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func OpenBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	cmd.Start()
}
