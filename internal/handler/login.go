package handler

import (
	"net/http"

	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type LoginHandler struct {
	loginService *service.LoginService
	provider     upstream.Provider
	devMode      bool
	brandName    string
}

func NewLoginHandler(loginService *service.LoginService, provider upstream.Provider, devMode bool, brandName string) *LoginHandler {
	return &LoginHandler{
		loginService: loginService,
		provider:     provider,
		devMode:      devMode,
		brandName:    brandName,
	}
}

// HandleLogin handles GET /login?authRequestID=xxx
func (h *LoginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("authRequestID")
	sessionID := getSessionCookie(r)
	info := clientinfo.FromContext(r.Context())

	result := h.loginService.HandleLogin(r.Context(), authRequestID, sessionID, info.IP, info.UserAgent)

	switch result.Action {
	case service.ActionRedirectToIdP:
		h.provider.Redirect(w, r, result.AuthRequestID)

	case service.ActionAutoApprove:
		// Redirect back to zitadel's authorize callback
		//nolint:gosec // Internal redirect to the fixed OIDC callback with a service-issued auth request ID.
		http.Redirect(w, r, "/authorize/callback?id="+result.AuthRequestID, http.StatusFound)

	case service.ActionError:
		h.renderError(w, result.ErrorCode, result.Error)
	}
}

// HandleCallback handles GET /login/callback?code=xxx&state=authRequestID
func (h *LoginHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	info := clientinfo.FromContext(r.Context())

	h.provider.Callback(w, r, func(w http.ResponseWriter, r *http.Request, state string, userInfo *upstream.UserInfo) {
		result := h.loginService.CompleteBrowserLogin(r.Context(), state, userInfo, info.IP, info.UserAgent)

		switch result.Action {
		case service.ActionAutoApprove:
			if result.SessionID != "" {
				setSessionCookie(w, result.SessionID, h.devMode)
			}
			//nolint:gosec // Internal redirect to the fixed OIDC callback with a service-issued auth request ID.
			http.Redirect(w, r, "/authorize/callback?id="+result.AuthRequestID, http.StatusFound)

		case service.ActionError:
			h.renderError(w, result.ErrorCode, result.Error)
		}
	})
}

func (h *LoginHandler) renderError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = pages.RenderError(w, pages.ErrorData{BrandName: h.brandName, Code: code, Message: message})
}
