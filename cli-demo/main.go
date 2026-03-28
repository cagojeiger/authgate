package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	authgateURL = "http://localhost:8080"
	clientID    = "service-a-cli"
)

type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func main() {
	fmt.Println("╔════════════════════════════════════════╗")
	fmt.Println("║     authgate CLI Demo                  ║")
	fmt.Println("║     Device Authorization Flow          ║")
	fmt.Println("╚════════════════════════════════════════╝")
	fmt.Println()

	// Step 1: Request device authorization
	fmt.Println("📡 Requesting device authorization...")
	deviceAuth, err := requestDeviceAuth()
	if err != nil {
		fmt.Printf("❌ Failed: %v\n", err)
		os.Exit(1)
	}

	// Step 2: Display instructions
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println("🔐 Authentication Required")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()
	fmt.Printf("User Code: %s\n", deviceAuth.UserCode)
	fmt.Println()
	fmt.Println("1. Open this URL in your browser:")
	fmt.Printf("   %s\n", deviceAuth.VerificationURIComplete)
	fmt.Println()
	fmt.Println("2. Or go to:")
	fmt.Printf("   %s\n", deviceAuth.VerificationURI)
	fmt.Printf("   and enter code: %s\n", deviceAuth.UserCode)
	fmt.Println()
	fmt.Println("3. Login and approve the request")
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	// Wait for user confirmation (optional)
	fmt.Print("Press Enter after approving in browser...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	// Step 3: Poll for token
	fmt.Println("⏳ Waiting for authorization...")
	token, err := pollForToken(deviceAuth.DeviceCode, deviceAuth.Interval, deviceAuth.ExpiresIn)
	if err != nil {
		fmt.Printf("❌ Failed: %v\n", err)
		os.Exit(1)
	}

	// Step 4: Display success
	fmt.Println()
	fmt.Println("✅ Successfully authenticated!")
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println("🔑 Token Information")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Printf("Access Token:  %s...%s\n", token.AccessToken[:20], token.AccessToken[len(token.AccessToken)-20:])
	fmt.Printf("Token Type:    %s\n", token.TokenType)
	fmt.Printf("Expires In:    %d seconds\n", token.ExpiresIn)
	fmt.Printf("Refresh Token: %s...%s\n", token.RefreshToken[:10], token.RefreshToken[len(token.RefreshToken)-10:])
	fmt.Printf("Scope:         %s\n", token.Scope)
	fmt.Println()

	// Save to file
	saveToken(token)
	fmt.Println("💾 Token saved to ~/.authgate/token.json")
	fmt.Println()
	fmt.Println("You can now use this token to access protected APIs!")
}

func requestDeviceAuth() (*DeviceAuthResponse, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", "openid profile email")

	resp, err := http.PostForm(authgateURL+"/oauth/device/authorize", data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
	}

	var deviceAuth DeviceAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceAuth); err != nil {
		return nil, err
	}

	return &deviceAuth, nil
}

func pollForToken(deviceCode string, interval, expiresIn int) (*TokenResponse, error) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	timeout := time.After(time.Duration(expiresIn) * time.Second)

	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("authorization timeout")
		case <-ticker.C:
			token, pending, err := requestToken(deviceCode)
			if err != nil {
				return nil, err
			}
			if !pending {
				return token, nil
			}
			fmt.Println("  Still waiting... (check your browser)")
		}
	}
}

func requestToken(deviceCode string) (*TokenResponse, bool, error) {
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("device_code", deviceCode)
	data.Set("client_id", clientID)

	resp, err := http.PostForm(authgateURL+"/oauth/token", data)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var token TokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
			return nil, false, err
		}
		return &token, false, nil
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		return nil, false, err
	}

	if errResp.Error == "authorization_pending" || errResp.Error == "slow_down" {
		return nil, true, nil
	}

	return nil, false, fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
}

func saveToken(token *TokenResponse) {
	home, _ := os.UserHomeDir()
	authgateDir := home + "/.authgate"
	os.MkdirAll(authgateDir, 0700)

	file, _ := os.Create(authgateDir + "/token.json")
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(token)
}
