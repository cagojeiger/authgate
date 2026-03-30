// demo-cli: CLI device flow login demo.
// Usage: go run demo/cli/main.go
// Runs locally (not in Docker) — opens browser for approval.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/kangheeyong/authgate/demo/shared"
)

var (
	authgateURL = shared.EnvOr("AUTHGATE_URL", "http://localhost:8080")
	clientID    = shared.EnvOr("CLIENT_ID", "cli-client")
)

func main() {
	fmt.Println("=== authgate demo-cli (Device Flow) ===")
	fmt.Println()

	result, err := shared.DeviceAuthorize(authgateURL, clientID)
	if err != nil {
		log.Fatalf("Device authorization failed: %v", err)
	}

	userCode, _ := result["user_code"].(string)
	deviceCode, _ := result["device_code"].(string)
	verURL, _ := result["verification_uri_complete"].(string)
	interval := 5
	if v, ok := result["interval"].(float64); ok {
		interval = int(v)
	}

	fmt.Printf("  User Code: %s\n", userCode)
	fmt.Printf("  Open:      %s\n", verURL)
	fmt.Println()
	fmt.Print("Press Enter to open browser...")
	bufio.NewReader(os.Stdin).ReadString('\n')
	shared.OpenBrowser(verURL)

	fmt.Println("Waiting for approval...")
	for {
		time.Sleep(time.Duration(interval) * time.Second)
		body, status := shared.DevicePoll(authgateURL, deviceCode, clientID)
		var tokens map[string]any
		json.Unmarshal(body, &tokens)

		if status == 200 {
			at, _ := tokens["access_token"].(string)
			rt, _ := tokens["refresh_token"].(string)
			ui := shared.GetUserinfo(authgateURL, at)
			fmt.Println("\n=== Login Success ===")
			fmt.Printf("  User:          %v\n", ui["name"])
			fmt.Printf("  Email:         %v\n", ui["email"])
			fmt.Printf("  Access Token:  %s...\n", at[:min(40, len(at))])
			fmt.Printf("  Refresh Token: %s\n", rt)

			fmt.Println("\n--- Refresh test ---")
			newTokens, err := shared.RefreshToken(authgateURL, rt, clientID)
			if err != nil {
				fmt.Printf("  Refresh failed: %v\n", err)
			} else {
				nat := newTokens["access_token"].(string)
				fmt.Printf("  New token: %s...\n", nat[:min(40, len(nat))])
				fmt.Println("  Refresh: OK")
			}
			return
		}

		if e, _ := tokens["error"].(string); e == "authorization_pending" || e == "slow_down" {
			fmt.Print(".")
			continue
		}
		fmt.Printf("\nError: %s\n", string(body))
		return
	}
}
