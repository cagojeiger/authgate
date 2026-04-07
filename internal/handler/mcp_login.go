package handler

import (
	"net/http"

	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/service"
)

type MCPLoginHandler struct {
	loginService *service.MCPLoginService
	devMode      bool
}

func NewMCPLoginHandler(loginService *service.MCPLoginService, devMode bool) *MCPLoginHandler {
	return &MCPLoginHandler{
		loginService: loginService,
		devMode:      devMode,
	}
}

// HandleLogin handles GET /mcp/login?authRequestID=xxx
func (h *MCPLoginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("authRequestID")
	sessionID := getSessionCookie(r)

	result := h.loginService.HandleLogin(r.Context(), authRequestID, sessionID, r.RemoteAddr, r.UserAgent())

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

// HandleCallback handles GET /mcp/callback?code=xxx&state=authRequestID
func (h *MCPLoginHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	authRequestID := r.URL.Query().Get("state")

	result := h.loginService.HandleCallback(r.Context(), code, authRequestID, r.RemoteAddr, r.UserAgent())

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

func (h *MCPLoginHandler) renderError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	pages.RenderError(w, pages.ErrorData{Code: code, Message: message})
}
