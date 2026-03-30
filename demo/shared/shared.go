// Package shared provides OAuth helpers and utilities for all demo binaries.
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
