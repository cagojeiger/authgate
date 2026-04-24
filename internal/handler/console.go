package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/kangheeyong/authgate/internal/service"
)

type consoleServicer interface {
	ListClients(ctx context.Context, sessionID, authHeader string) *service.ClientsResult
	ListConnections(ctx context.Context, sessionID, authHeader string) *service.ConnectionsResult
	RevokeConnection(ctx context.Context, sessionID, authHeader, clientID string) *service.RevokeConnectionResult
	ListSessions(ctx context.Context, sessionID, authHeader string) *service.SessionsResult
	RevokeSession(ctx context.Context, sessionID, authHeader, revokeSessionID string) *service.RevokeSessionResult
	RevokeOtherSessions(ctx context.Context, sessionID, authHeader string) *service.RevokeOtherSessionsResult
	GetAuditLog(ctx context.Context, sessionID, authHeader string, page, limit int) *service.AuditLogResult
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

func (h *ConsoleHandler) HandleListSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	result := h.svc.ListSessions(r.Context(), getSessionCookie(r), r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")
	if result.ErrorCode != 0 {
		w.WriteHeader(result.ErrorCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(result.ErrorCode)})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"sessions": result.Sessions})
}

func (h *ConsoleHandler) HandleRevokeSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	result := h.svc.RevokeSession(r.Context(), getSessionCookie(r), r.Header.Get("Authorization"), r.PathValue("id"))
	if result.ErrorCode != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.ErrorCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(result.ErrorCode)})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ConsoleHandler) HandleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	result := h.svc.RevokeOtherSessions(r.Context(), getSessionCookie(r), r.Header.Get("Authorization"))
	if result.ErrorCode != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.ErrorCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(result.ErrorCode)})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ConsoleHandler) HandleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	result := h.svc.GetAuditLog(r.Context(), getSessionCookie(r), r.Header.Get("Authorization"), page, limit)
	w.Header().Set("Content-Type", "application/json")
	if result.ErrorCode != 0 {
		w.WriteHeader(result.ErrorCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(result.ErrorCode)})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"events": result.Events,
		"page":   result.Page,
		"limit":  result.Limit,
		"total":  result.Total,
	})
}
