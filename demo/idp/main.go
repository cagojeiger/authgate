// demo-idp: standalone mock IdP server simulating Google OAuth.
// Usage: go run demo/idp/main.go
// Docker: serves on :8082
package main

import (
	"log"
	"log/slog"
	"net/http"

	"github.com/kangheeyong/authgate/demo/shared"
)

func main() {
	addr := shared.EnvOr("LISTEN_ADDR", ":8082")
	pub := shared.EnvOr("PUBLIC_URL", "http://localhost:8082")

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", shared.MockDiscoveryHandler(pub))
	mux.HandleFunc("/authorize", shared.MockAuthorize)
	mux.HandleFunc("/token", shared.MockToken)
	mux.HandleFunc("/userinfo", shared.MockUserinfo)

	slog.Info("demo-idp starting", "addr", addr, "publicURL", pub)
	log.Fatal(http.ListenAndServe(addr, mux))
}
