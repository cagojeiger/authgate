package handler

import (
	"net/http"

	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/service"
)

const sessionCookieName = "authgate_session"

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

	case service.ActionShowTerms:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pages.RenderTerms(w, pages.TermsData{AuthRequestID: result.AuthRequestID})

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
		h.setSessionCookie(w, result.SessionID)
	}

	switch result.Action {
	case service.ActionShowTerms:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pages.RenderTerms(w, pages.TermsData{AuthRequestID: result.AuthRequestID, Error: result.Error})

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
		h.setSessionCookie(w, result.SessionID)
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

// HandleTermsPage handles GET /login/terms — renders the terms page directly.
func (h *LoginHandler) HandleTermsPage(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("authRequestID")
	if authRequestID == "" {
		h.renderError(w, http.StatusBadRequest, "missing authRequestID")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	pages.RenderTerms(w, pages.TermsData{AuthRequestID: authRequestID})
}

// HandleTermsSubmit handles POST /login/terms
func (h *LoginHandler) HandleTermsSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, http.StatusBadRequest, "invalid form")
		return
	}

	authRequestID := r.FormValue("authRequestID")
	termsAgree := r.FormValue("terms_agree") == "on"
	privacyAgree := r.FormValue("privacy_agree") == "on"
	ageConfirm := r.FormValue("age_confirm") == "on"
	sessionID := getSessionCookie(r)
	ipAddress := r.RemoteAddr
	userAgent := r.UserAgent()

	result := h.loginService.HandleTermsSubmit(r.Context(), authRequestID, sessionID, termsAgree, privacyAgree, ageConfirm, ipAddress, userAgent)

	switch result.Action {
	case service.ActionShowTerms:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK) // 200 + re-render (Spec 002)
		pages.RenderTerms(w, pages.TermsData{AuthRequestID: result.AuthRequestID, Error: result.Error})

	case service.ActionAutoApprove:
		http.Redirect(w, r, "/authorize/callback?id="+result.AuthRequestID, http.StatusFound)

	case service.ActionError:
		h.renderError(w, result.ErrorCode, result.Error)
	}
}

func (h *LoginHandler) renderError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	pages.RenderError(w, pages.ErrorData{Code: code, Message: message})
}

func (h *LoginHandler) setSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   !h.devMode,
	})
}

func getSessionCookie(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}
