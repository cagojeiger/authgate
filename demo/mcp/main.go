// demo-mcp: MCP SSE server with OAuth token validation.
// Docker mode (default): SSE server on :9091, validates tokens via authgate /userinfo.
// Local mode:  go run demo/mcp/main.go --local  → does OAuth login first, then starts SSE.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/kangheeyong/authgate/demo/shared"
)

var (
	authgatePublic   = shared.EnvOr("AUTHGATE_PUBLIC_URL", "http://localhost:8080")
	authgateInternal = shared.EnvOr("AUTHGATE_INTERNAL_URL", authgatePublic)
	clientID         = shared.EnvOr("CLIENT_ID", "mcp-client")
	listenAddr       = shared.EnvOr("LISTEN_ADDR", ":9091")
)

func main() {
	localMode := len(os.Args) > 1 && os.Args[1] == "--local"

	if localMode {
		runLocal()
	} else {
		runServer()
	}
}

// runServer: Docker mode — SSE server that validates any authgate token.
func runServer() {
	mux := http.NewServeMux()

	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || len(auth) < 8 {
			http.Error(w, `{"error":"missing Authorization header"}`, 401)
			return
		}
		token := auth[7:] // strip "Bearer "

		// Validate token by calling authgate /userinfo
		ui := shared.GetUserinfo(authgateInternal, token)
		if _, ok := ui["error"]; ok {
			http.Error(w, `{"error":"invalid_token"}`, 401)
			return
		}
		if ui["sub"] == nil {
			http.Error(w, `{"error":"invalid_token"}`, 401)
			return
		}

		// SSE stream
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", 500)
			return
		}

		userName, _ := ui["name"].(string)
		userEmail, _ := ui["email"].(string)
		fmt.Fprintf(w, "event: connected\ndata: {\"user\":\"%s\",\"email\":\"%s\"}\n\n", userName, userEmail)
		flusher.Flush()

		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		seq := 0
		for {
			select {
			case <-r.Context().Done():
				return
			case t := <-ticker.C:
				seq++
				fmt.Fprintf(w, "event: heartbeat\ndata: {\"seq\":%d,\"time\":\"%s\"}\n\n", seq, t.Format(time.RFC3339))
				flusher.Flush()
			}
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"service":  "demo-mcp (SSE)",
			"endpoint": "/events",
			"auth":     "Bearer <access_token from authgate>",
			"usage":    "1. Login via demo-app, 2. curl -N -H 'Authorization: Bearer <token>' http://localhost:9091/events",
		})
	})

	slog.Info("demo-mcp starting (server mode)", "addr", listenAddr, "authgate", authgateInternal)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

// runLocal: interactive mode — does MCP OAuth login, then starts SSE server.
func runLocal() {
	fmt.Println("=== authgate demo-mcp (OAuth + SSE) ===")
	fmt.Println()

	verifier := shared.RandomString(43)
	challenge := shared.S256(verifier)
	state := shared.RandomString(16)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://localhost:%d/callback", port)

	fmt.Printf("  Client:   %s\n", clientID)
	fmt.Printf("  Callback: %s\n", redirectURI)
	fmt.Println()

	params := url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI},
		"response_type": {"code"}, "scope": {"openid profile email offline_access"},
		"state": {state}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	authorizeURL := authgatePublic + "/authorize?" + params.Encode()

	codeCh := make(chan string, 1)
	errCh := make(chan string, 1)

	cbMux := http.NewServeMux()
	cbMux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if e := r.URL.Query().Get("error"); e != "" {
			w.Write([]byte("Error: " + e + "\nClose this window."))
			errCh <- e
			return
		}
		w.Write([]byte("Authorization complete! Close this window."))
		codeCh <- r.URL.Query().Get("code")
	})
	srv := &http.Server{Handler: cbMux}
	go srv.Serve(listener)

	fmt.Println("Opening browser for MCP authentication...")
	shared.OpenBrowser(authorizeURL)
	fmt.Println("Waiting for callback...")

	select {
	case code := <-codeCh:
		srv.Shutdown(context.Background())
		tokens, err := shared.ExchangeCode(authgatePublic, code, clientID, redirectURI, verifier)
		if err != nil {
			log.Fatalf("Token exchange failed: %v", err)
		}
		at, _ := tokens["access_token"].(string)
		rt, _ := tokens["refresh_token"].(string)
		ui := shared.GetUserinfo(authgatePublic, at)

		fmt.Println("\n=== MCP Login Success ===")
		fmt.Printf("  User:          %v\n", ui["name"])
		fmt.Printf("  Email:         %v\n", ui["email"])
		fmt.Printf("  Access Token:  %s...\n", at[:min(40, len(at))])
		fmt.Printf("  Refresh Token: %s\n", rt)

		fmt.Println("\n--- SSE server on :9091 ---")
		fmt.Printf("  curl -N -H \"Authorization: Bearer %s...\" http://localhost:9091/events\n", at[:min(20, len(at))])
		fmt.Println("  Ctrl+C to stop")

		// Override authgateInternal to public for local mode
		authgateInternal = authgatePublic
		listenAddr = ":9091"
		runServer()

	case e := <-errCh:
		srv.Shutdown(context.Background())
		log.Fatalf("Auth error: %s", e)

	case <-time.After(2 * time.Minute):
		srv.Shutdown(context.Background())
		log.Fatal("Timeout waiting for callback")
	}
}
