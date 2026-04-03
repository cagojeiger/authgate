package handler

import (
	"net/http"

	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/service"
)

type LoginHandler struct {
	loginService *service.LoginService
	devMode      bool
}

func NewLoginHandler(loginService *service.LoginService, devMode bool) *LoginHandler {
	return &LoginHandler{
		loginService: loginService,
		devMode:      devMode,
	}
}

// HandleLogin handles GET /login?authRequestID=xxx
func (h *LoginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("authRequestID")
	sessionID := getSessionCookie(r)

	result := h.loginService.HandleLogin(r.Context(), authRequestID, sessionID, r.RemoteAddr, r.UserAgent())

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

// HandleMCPLogin handles GET /mcp/login?authRequestID=xxx
func (h *LoginHandler) HandleMCPLogin(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("authRequestID")
	sessionID := getSessionCookie(r)

	result := h.loginService.HandleMCPLogin(r.Context(), authRequestID, sessionID, r.RemoteAddr, r.UserAgent())

	switch result.Action {
	case service.ActionRedirectToIdP:
		http.Redirect(w, r, result.RedirectURL, http.StatusFound)

	case service.ActionAutoApprove:
		http.Redirect(w, r, "/authorize/callback?id="+result.AuthRequestID, http.StatusFound)

	case service.ActionError:
		h.renderError(w, result.ErrorCode, result.Error)

	default:
		h.renderError(w, http.StatusInternalServerError, "invalid mcp login action")
	}
}

// HandleCallback handles GET /login/callback?code=xxx&state=authRequestID
func (h *LoginHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	authRequestID := r.URL.Query().Get("state")
	ipAddress := r.RemoteAddr
	userAgent := r.UserAgent()

	result := h.loginService.HandleCallback(r.Context(), code, authRequestID, ipAddress, userAgent)

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

// HandleMCPCallback handles GET /mcp/callback?code=xxx&state=authRequestID
func (h *LoginHandler) HandleMCPCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	authRequestID := r.URL.Query().Get("state")
	ipAddress := r.RemoteAddr
	userAgent := r.UserAgent()

	result := h.loginService.HandleMCPCallback(r.Context(), code, authRequestID, ipAddress, userAgent)

	if result.SessionID != "" {
		setSessionCookie(w, result.SessionID, h.devMode)
	}

	switch result.Action {
	case service.ActionAutoApprove:
		http.Redirect(w, r, "/authorize/callback?id="+result.AuthRequestID, http.StatusFound)

	case service.ActionError:
		h.renderError(w, result.ErrorCode, result.Error)

	default:
		h.renderError(w, http.StatusInternalServerError, "invalid mcp callback action")
	}
}

func (h *LoginHandler) renderError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	pages.RenderError(w, pages.ErrorData{Code: code, Message: message})
}
