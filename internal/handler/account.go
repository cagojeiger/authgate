package handler

import (
	"encoding/json"
	"net/http"

	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/storage"
)

type AccountHandler struct {
	accountService *service.AccountService
	store          *storage.Storage
}

func NewAccountHandler(accountService *service.AccountService, store *storage.Storage) *AccountHandler {
	return &AccountHandler{accountService: accountService, store: store}
}

// HandleDeleteAccount handles DELETE /account
func (h *AccountHandler) HandleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	sessionID := getSessionCookie(r)
	if sessionID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	user, err := h.store.GetValidSession(r.Context(), sessionID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid session"})
		return
	}

	result := h.accountService.RequestDeletion(r.Context(), user.ID, r.RemoteAddr, r.UserAgent())

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
