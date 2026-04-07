package service

import (
	"context"
	"time"

	"github.com/kangheeyong/authgate/internal/upstream"
)

// MCPLoginService owns MCP channel login/callback orchestration.
// It reuses existing LoginService flow logic while exposing MCP-only entrypoints.
type MCPLoginService struct {
	base *LoginService
}

func NewMCPLoginService(store LoginStore, mcpProvider upstream.Provider, sessionTTL time.Duration) *MCPLoginService {
	base := &LoginService{
		store:           store,
		browserProvider: mcpProvider,
		mcpProvider:     mcpProvider,
		sessionTTL:      sessionTTL,
	}
	return &MCPLoginService{base: base}
}

func (s *MCPLoginService) HandleLogin(ctx context.Context, authRequestID, sessionID, ipAddress, userAgent string) *LoginResult {
	return s.base.HandleMCPLogin(ctx, authRequestID, sessionID, ipAddress, userAgent)
}

func (s *MCPLoginService) HandleCallback(ctx context.Context, code, authRequestID, ipAddress, userAgent string) *CallbackResult {
	return s.base.HandleMCPCallback(ctx, code, authRequestID, ipAddress, userAgent)
}

