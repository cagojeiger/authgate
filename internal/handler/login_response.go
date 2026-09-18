package handler

import (
	"net/http"

	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/upstream"
)

// writeLoginResult translates the shared browser/MCP login result into HTTP.
// Unknown actions remain the caller's responsibility: MCP renders an error,
// while the browser handler historically leaves the response untouched.
func writeLoginResult(w http.ResponseWriter, r *http.Request, result *service.LoginResult, provider upstream.Provider, brand pages.Brand) bool {
	switch result.Action {
	case service.ActionRedirectToIdP:
		var opts []upstream.RedirectOption
		if result.UpstreamPrompt != "" {
			opts = append(opts, upstream.WithPrompt(result.UpstreamPrompt))
		}
		provider.Redirect(w, r, result.AuthRequestID, opts...)
	case service.ActionAutoApprove:
		redirectToAuthorizationCallback(w, r, result.AuthRequestID)
	case service.ActionRedirectToClient:
		//nolint:gosec // The auth request redirect_uri was validated by zitadel.
		http.Redirect(w, r, result.RedirectURL, http.StatusFound)
	case service.ActionError:
		renderError(w, brand, result.ErrorCode, result.Error)
	default:
		return false
	}
	return true
}

// writeCallbackResult sets a session cookie only after a successful callback.
// In particular, authorization errors must never establish a browser session.
func writeCallbackResult(w http.ResponseWriter, r *http.Request, result *service.CallbackResult, devMode bool, brand pages.Brand) bool {
	switch result.Action {
	case service.ActionAutoApprove:
		if result.SessionID != "" {
			setSessionCookie(w, result.SessionID, devMode)
		}
		redirectToAuthorizationCallback(w, r, result.AuthRequestID)
	case service.ActionRedirectToClient:
		//nolint:gosec // The auth request redirect_uri was validated by zitadel.
		http.Redirect(w, r, result.RedirectURL, http.StatusFound)
	case service.ActionError:
		renderError(w, brand, result.ErrorCode, result.Error)
	default:
		return false
	}
	return true
}

func redirectToAuthorizationCallback(w http.ResponseWriter, r *http.Request, authRequestID string) {
	//nolint:gosec // Internal fixed OIDC callback with a service-issued request ID.
	http.Redirect(w, r, "/authorize/callback?id="+authRequestID, http.StatusFound)
}

func renderError(w http.ResponseWriter, brand pages.Brand, code int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = pages.RenderError(w, pages.ErrorData{Brand: brand, Code: code, Message: message})
}
