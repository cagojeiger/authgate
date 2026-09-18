package service

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

// Entry and callback intentionally have different expired-request responses.
// Sharing their lookup machinery must not silently change the HTTP contract.
func TestAuthRequestLookupErrors_PreserveEntryAndCallbackContracts(t *testing.T) {
	for _, tc := range []struct {
		name          string
		err           error
		entryError    string
		entryCode     int
		callbackError string
		callbackCode  int
	}{
		{"missing", storage.ErrNotFound, "auth_request_not_found", http.StatusBadRequest, "auth_request_not_found", http.StatusBadRequest},
		{"expired", oidc.ErrInvalidRequest(), "auth_request_expired", http.StatusBadRequest, "internal_error", http.StatusInternalServerError},
		{"database error", errors.New("database unavailable"), "internal_error", http.StatusInternalServerError, "internal_error", http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeLoginStore{getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) { return nil, tc.err }}
			browser := NewLoginService(store, "google", "https://authgate.example", 0)
			mcp := NewMCPLoginService(store, "google", "https://authgate.example", 0)
			for channel, login := range map[string]func(context.Context, string, string, string, string) *LoginResult{
				"browser": browser.HandleLogin, "mcp": mcp.HandleLogin,
			} {
				result := login(context.Background(), "ar-1", "", "", "")
				if result.Action != ActionError || result.Error != tc.entryError || result.ErrorCode != tc.entryCode {
					t.Errorf("%s entry = %+v", channel, result)
				}
			}
			for channel, callback := range map[string]func(context.Context, string, *upstream.UserInfo, string, string) *CallbackResult{
				"browser": browser.CompleteBrowserLogin, "mcp": mcp.CompleteMCPLogin,
			} {
				result := callback(context.Background(), "ar-1", &upstream.UserInfo{Sub: "subject"}, "", "")
				if result.Action != ActionError || result.Error != tc.callbackError || result.ErrorCode != tc.callbackCode || result.SessionID != "" {
					t.Errorf("%s callback = %+v", channel, result)
				}
			}
		})
	}
}
