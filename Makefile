.PHONY: infra infra-down dev dev-authgate dev-sample-app stop sqlc-generate

# Start infrastructure (DB + mock IdP)
infra:
	docker compose up -d
	@echo "Waiting for DB..."
	@until docker compose exec db pg_isready -U authgate > /dev/null 2>&1; do sleep 1; done
	@echo "Infrastructure ready: db=:5433 mock-idp=:8082"

# Stop infrastructure
infra-down:
	docker compose down -v

# Start authgate (localhost:8080)
dev-authgate:
	DATABASE_URL="postgres://authgate:authgate@localhost:5433/authgate?sslmode=disable" \
	SESSION_SECRET="test-session-secret-32chars-long!" \
	PUBLIC_URL="http://localhost:8080" \
	DEV_MODE=true \
	OIDC_ISSUER_URL="http://localhost:8082" \
	OIDC_CLIENT_ID=authgate \
	OIDC_CLIENT_SECRET=fake-secret \
	go run ./cmd/authgate/

# Start mcp-server (localhost:9091)
dev-mcp-server:
	cd examples/mcp-server && \
	AUTHGATE_URL="http://localhost:8080" \
	LISTEN_ADDR=":9091" \
	go run .

# Start sample-app (localhost:9090)
dev-sample-app:
	cd examples/webapp && \
	AUTHGATE_ISSUER="http://localhost:8080" \
	AUTHGATE_BROWSER_URL="http://localhost:8080" \
	CLIENT_ID=sample-app \
	SELF_URL="http://localhost:9090" \
	LISTEN_ADDR=":9090" \
	go run .

# Start everything (run in separate terminals)
dev:
	@echo "Run these in separate terminals:"
	@echo "  make infra           # 1. Start DB + mock IdP"
	@echo "  make dev-authgate    # 2. Start authgate (:8080)"
	@echo "  make dev-sample-app  # 3. Start sample-app (:9090)"
	@echo "  make dev-mcp-server  # 4. Start MCP server (:9091)"
	@echo ""
	@echo "Then open http://localhost:9090"
	@echo "Device flow: cd examples/cli && go run ."

# Stop everything
stop:
	-@pkill -f "go run ./cmd/authgate/" 2>/dev/null
	-@pkill -f "go run ." 2>/dev/null
	docker compose down -v
	@echo "Stopped"

# Generate sqlc query code (Docker-based, no local sqlc install needed)
sqlc-generate:
	docker run --rm -v $(CURDIR):/src -w /src sqlc/sqlc:1.28.0 generate
