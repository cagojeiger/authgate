package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/kangheeyong/authgate/internal/service"
)

type consoleServicer interface {
	ListClients(ctx context.Context, sessionID, authHeader string) *service.ClientsResult
	ListConnections(ctx context.Context, sessionID, authHeader string) *service.ConnectionsResult
	RevokeConnection(ctx context.Context, sessionID, authHeader, clientID string) *service.RevokeConnectionResult
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
	result := h.svc.ListClients(r.Context(), getSessionCookie(r), r.Header.Get("Authorization"))
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
	result := h.svc.ListConnections(r.Context(), getSessionCookie(r), r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")
	if result.ErrorCode != 0 {
		w.WriteHeader(result.ErrorCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(result.ErrorCode)})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"connections": result.Connections})
}

func (h *ConsoleHandler) HandleRevokeConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	result := h.svc.RevokeConnection(r.Context(), getSessionCookie(r), r.Header.Get("Authorization"), r.PathValue("client_id"))
	if result.ErrorCode != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.ErrorCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(result.ErrorCode)})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
