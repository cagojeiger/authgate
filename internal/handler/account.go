package handler

import (
	"encoding/json"
	"net/http"

	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/service"
)

type AccountHandler struct {
	accountService         *service.AccountService
	publicURL              string
	accountDeletionEnabled bool
}

func NewAccountHandler(accountService *service.AccountService, publicURL string, accountDeletionEnabled ...bool) *AccountHandler {
	enabled := true
	if len(accountDeletionEnabled) > 0 {
		enabled = accountDeletionEnabled[0]
	}
	return &AccountHandler{accountService: accountService, publicURL: publicURL, accountDeletionEnabled: enabled}
}

// HandleDeleteAccount handles DELETE /account
func (h *AccountHandler) HandleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if !h.accountDeletionEnabled {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "account deletion disabled"})
		return
	}

	// Origin validation for destructive action.
	// Require Origin to be present and match publicURL — protects against
	// non-browser clients (curl, etc.) bypassing CSRF protection.
	origin := r.Header.Get("Origin")
	if origin == "" || origin != h.publicURL {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "origin mismatch"})
		return
	}

	sessionID := getSessionCookie(r)
	info := clientinfo.FromContext(r.Context())

	result := h.accountService.RequestDeletion(r.Context(), sessionID, info.IP, info.UserAgent)

	w.Header().Set("Content-Type", "application/json")
	if result.Success {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "pending_deletion",
			"message": result.Message,
		})
	} else {
		w.WriteHeader(result.ErrorCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": result.Message})
	}
}
