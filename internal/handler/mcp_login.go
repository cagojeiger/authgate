package handler

import (
	"net/http"

	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type MCPLoginHandler struct {
	loginService *service.MCPLoginService
	provider     upstream.Provider
	devMode      bool
	brand        pages.Brand
}

func NewMCPLoginHandler(loginService *service.MCPLoginService, provider upstream.Provider, devMode bool, brand pages.Brand) *MCPLoginHandler {
	return &MCPLoginHandler{
		loginService: loginService,
		provider:     provider,
		devMode:      devMode,
		brand:        brand,
	}
}

// HandleLogin handles GET /mcp/login?authRequestID=xxx
func (h *MCPLoginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("authRequestID")
	sessionID := getSessionCookie(r)
	info := clientinfo.FromContext(r.Context())

	result := h.loginService.HandleLogin(r.Context(), authRequestID, sessionID, info.IP, info.UserAgent)

	switch result.Action {
	case service.ActionRedirectToIdP:
		h.provider.Redirect(w, r, result.AuthRequestID)
	case service.ActionAutoApprove:
		//nolint:gosec // Internal redirect to the fixed OIDC callback with a service-issued auth request ID.
		http.Redirect(w, r, "/authorize/callback?id="+result.AuthRequestID, http.StatusFound)
	case service.ActionError:
		h.renderError(w, result.ErrorCode, result.Error)
	default:
		h.renderError(w, http.StatusInternalServerError, "invalid mcp login action")
	}
}

// HandleCallback handles GET /mcp/callback?code=xxx&state=authRequestID
func (h *MCPLoginHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	info := clientinfo.FromContext(r.Context())

	h.provider.Callback(w, r, func(w http.ResponseWriter, r *http.Request, state string, userInfo *upstream.UserInfo) {
		result := h.loginService.CompleteMCPLogin(r.Context(), state, userInfo, info.IP, info.UserAgent)

		switch result.Action {
		case service.ActionAutoApprove:
			if result.SessionID != "" {
				setSessionCookie(w, result.SessionID, h.devMode)
			}
			//nolint:gosec // Internal redirect to the fixed OIDC callback with a service-issued auth request ID.
			http.Redirect(w, r, "/authorize/callback?id="+result.AuthRequestID, http.StatusFound)
		case service.ActionError:
			h.renderError(w, result.ErrorCode, result.Error)
		default:
			h.renderError(w, http.StatusInternalServerError, "invalid mcp callback action")
		}
	})
}

func (h *MCPLoginHandler) renderError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = pages.RenderError(w, pages.ErrorData{Brand: h.brand, Code: code, Message: message})
}
