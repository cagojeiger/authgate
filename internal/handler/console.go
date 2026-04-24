package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/kangheeyong/authgate/internal/service"
)

type consoleServicer interface {
	ListClients(ctx context.Context, sessionID string) *service.ClientsResult
	ListConnections(ctx context.Context, sessionID string) *service.ConnectionsResult
}

type ConsoleHandler struct {
	svc consoleServicer
}

func NewConsoleHandler(svc consoleServicer) *ConsoleHandler {
	return &ConsoleHandler{svc: svc}
}

func (h *ConsoleHandler) HandleListClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	result := h.svc.ListClients(r.Context(), getSessionCookie(r))
	w.Header().Set("Content-Type", "application/json")
	if result.ErrorCode != 0 {
		w.WriteHeader(result.ErrorCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(result.ErrorCode)})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"clients": result.Clients})
}

func (h *ConsoleHandler) HandleListConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	result := h.svc.ListConnections(r.Context(), getSessionCookie(r))
	w.Header().Set("Content-Type", "application/json")
	if result.ErrorCode != 0 {
		w.WriteHeader(result.ErrorCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(result.ErrorCode)})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"connections": result.Connections})
}
