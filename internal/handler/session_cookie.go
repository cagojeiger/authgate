package handler

import "net/http"

const sessionCookieName = "authgate_session"

// setSessionCookie issues the browser session.
//
// SameSite is Lax rather than Strict, and it has to be. Every login ends with
// the upstream IdP redirecting to one of our callbacks, which mints the
// session and immediately redirects on — to /device?user_code=… for the device
// flow. WebKit decides whether that final hop is same-site by looking at the
// whole redirect chain, and the chain was started cross-site by the IdP, so a
// Strict cookie is withheld there. The device page then sees no session and
// bounces back to the IdP, which signs the user in again: the flow could not
// be completed in Safari at all. Chromium updates its site-for-cookies per
// hop and does send a Strict cookie, which is why this only ever broke on one
// engine. See internal/handler/session_cookie_test.go.
//
// Lax costs little here. It only adds the cookie to top-level cross-site GET
// navigations, and no GET endpoint acts on its own: /device merely renders the
// consent screen, and the state-changing POST /device/approve is guarded by
// the double-submit csrf_token, which stays Strict.
func setSessionCookie(w http.ResponseWriter, sessionID string, devMode bool) {
	//nolint:gosec // Secure=false is allowed only in explicit DEV_MODE for localhost development.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   !devMode,
	})
}

func getSessionCookie(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}
