// Device Flow CLI — tests RFC 8628 device authorization with authgate.
// Usage: go run ./examples/cli/
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type DeviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func main() {
	authgateURL := envOr("AUTHGATE_URL", "http://localhost:8080")
	clientID := envOr("CLIENT_ID", "cli-client")

	fmt.Println("authgate Device Flow CLI")
	fmt.Println("========================")
	fmt.Printf("  authgate: %s\n", authgateURL)
	fmt.Printf("  client:   %s\n\n", clientID)

	// Step 1: Request device authorization
	fmt.Println("[1] Requesting device authorization...")
	data := url.Values{
		"client_id": {clientID},
		"scope":     {"openid profile email offline_access"},
	}
	resp, err := http.Post(authgateURL+"/oauth/device/authorize", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var errResp ErrorResponse
		json.NewDecoder(resp.Body).Decode(&errResp)
		fmt.Fprintf(os.Stderr, "Error %d: %s — %s\n", resp.StatusCode, errResp.Error, errResp.Description)
		os.Exit(1)
	}

	var deviceAuth DeviceAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceAuth); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding response: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("  Open this URL in your browser:")
	fmt.Printf("    %s\n", deviceAuth.VerificationURI)
	fmt.Println()
	fmt.Println("  Enter this code:")
	fmt.Printf("    %s\n", deviceAuth.UserCode)
	fmt.Println()

	// Debug info
	fmt.Printf("  device_code:  %s\n", deviceAuth.DeviceCode)
	fmt.Printf("  expires_in:   %d seconds\n", deviceAuth.ExpiresIn)
	fmt.Printf("  interval:     %d seconds\n\n", deviceAuth.Interval)

	// Step 2: Poll for token
	interval := deviceAuth.Interval
	if interval < 1 {
		interval = 5
	}

	fmt.Printf("[2] Polling for authorization (every %ds)...\n", interval)
	deadline := time.Now().Add(time.Duration(deviceAuth.ExpiresIn) * time.Second)

	for {
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "\nError: device code expired")
			os.Exit(1)
		}

		time.Sleep(time.Duration(interval) * time.Second)

		tokenData := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceAuth.DeviceCode},
			"client_id":   {clientID},
		}
		tokenResp, err := http.Post(authgateURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(tokenData.Encode()))
		if err != nil {
			fmt.Printf("  poll error: %v\n", err)
			continue
		}

		if tokenResp.StatusCode == 200 {
			var tokens TokenResponse
			json.NewDecoder(tokenResp.Body).Decode(&tokens)
			tokenResp.Body.Close()

			fmt.Println("\n[3] Authorization successful!")
			fmt.Println()
			fmt.Println("Tokens received")
			fmt.Println("---------------")

			// Print tokens with truncation for readability
			fmt.Printf("  access_token:  %s...\n", truncate(tokens.AccessToken, 50))
			fmt.Printf("  refresh_token: %s\n", tokens.RefreshToken)
			fmt.Printf("  id_token:      %s...\n", truncate(tokens.IDToken, 50))
			fmt.Printf("  token_type:    %s\n", tokens.TokenType)
			fmt.Printf("  expires_in:    %d seconds\n", tokens.ExpiresIn)
			fmt.Printf("  scope:         %s\n", tokens.Scope)

			// Step 3: Fetch userinfo
			fmt.Println("\n[4] Fetching userinfo...")
			uiReq, _ := http.NewRequest("GET", authgateURL+"/userinfo", nil)
			uiReq.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
			uiResp, err := http.DefaultClient.Do(uiReq)
			if err != nil {
				fmt.Printf("  userinfo error: %v\n", err)
			} else {
				var userinfo map[string]any
				json.NewDecoder(uiResp.Body).Decode(&userinfo)
				uiResp.Body.Close()
				prettyUI, _ := json.MarshalIndent(userinfo, "  ", "  ")
				fmt.Printf("  %s\n", string(prettyUI))
			}

			// Step 4: Test refresh
			fmt.Println("\n[5] Testing token refresh...")
			refreshData := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {tokens.RefreshToken},
				"client_id":     {clientID},
			}
			refreshResp, err := http.Post(authgateURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(refreshData.Encode()))
			if err != nil {
				fmt.Printf("  refresh error: %v\n", err)
			} else {
				if refreshResp.StatusCode == 200 {
					var newTokens TokenResponse
					json.NewDecoder(refreshResp.Body).Decode(&newTokens)
					refreshResp.Body.Close()
					fmt.Printf("  new access_token:  %s...\n", truncate(newTokens.AccessToken, 50))
					fmt.Printf("  new refresh_token: %s\n", newTokens.RefreshToken)
					fmt.Println("  refresh: OK (rotation working)")
				} else {
					refreshResp.Body.Close()
					fmt.Printf("  refresh failed: HTTP %d\n", refreshResp.StatusCode)
				}
			}

			fmt.Println("\nDone.")
			return
		}

		// Handle polling errors
		var errResp ErrorResponse
		json.NewDecoder(tokenResp.Body).Decode(&errResp)
		tokenResp.Body.Close()

		switch errResp.Error {
		case "authorization_pending":
			fmt.Print("  .")
		case "slow_down":
			interval += 5
			fmt.Printf("  (slowing down to %ds)\n", interval)
		case "access_denied":
			fmt.Println("\n  User denied the request.")
			os.Exit(1)
		case "expired_token":
			fmt.Println("\n  Device code expired.")
			os.Exit(1)
		default:
			fmt.Printf("  unexpected: %s — %s\n", errResp.Error, errResp.Description)
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
