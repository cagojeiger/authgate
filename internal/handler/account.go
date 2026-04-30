package handler

import (
	"encoding/json"
	"net/http"

	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/service"
)

type AccountHandler struct {
	accountService *service.AccountService
	publicURL      string
}

func NewAccountHandler(accountService *service.AccountService, publicURL string) *AccountHandler {
	return &AccountHandler{accountService: accountService, publicURL: publicURL}
}

// HandleDeleteAccount handles DELETE /account
func (h *AccountHandler) HandleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Origin validation for destructive action
	if origin := r.Header.Get("Origin"); origin != "" {
		if origin != h.publicURL {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "origin mismatch"})
			return
		}
	}

	sessionID := getSessionCookie(r)
	info := clientinfo.FromContext(r.Context())

	result := h.accountService.RequestDeletion(r.Context(), sessionID, info.IP, info.UserAgent)

	w.Header().Set("Content-Type", "application/json")
	if result.Success {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "pending_deletion",
			"message": result.Message,
		})
	} else {
		w.WriteHeader(result.ErrorCode)
		json.NewEncoder(w).Encode(map[string]string{"error": result.Message})
	}
}
