package handler

import (
	"net/http"

	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/service"
)

type LoginHandler struct {
	loginService *service.LoginService
	devMode      bool
	brandName    string
}

func NewLoginHandler(loginService *service.LoginService, devMode bool, brandName string) *LoginHandler {
	return &LoginHandler{
		loginService: loginService,
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
		http.Redirect(w, r, result.RedirectURL, http.StatusFound)

	case service.ActionAutoApprove:
		// Redirect back to zitadel's authorize callback
		http.Redirect(w, r, "/authorize/callback?id="+result.AuthRequestID, http.StatusFound)

	case service.ActionError:
		h.renderError(w, result.ErrorCode, result.Error)
	}
}

// HandleCallback handles GET /login/callback?code=xxx&state=authRequestID
func (h *LoginHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	authRequestID := r.URL.Query().Get("state")
	info := clientinfo.FromContext(r.Context())

	result := h.loginService.HandleCallback(r.Context(), code, authRequestID, info.IP, info.UserAgent)

	if result.SessionID != "" {
		setSessionCookie(w, result.SessionID, h.devMode)
	}

	switch result.Action {
	case service.ActionAutoApprove:
		http.Redirect(w, r, "/authorize/callback?id="+result.AuthRequestID, http.StatusFound)

	case service.ActionError:
		h.renderError(w, result.ErrorCode, result.Error)
	}
}

func (h *LoginHandler) renderError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	pages.RenderError(w, pages.ErrorData{BrandName: h.brandName, Code: code, Message: message})
}
