package handler

import "net/http"

const sessionCookieName = "authgate_session"

func setSessionCookie(w http.ResponseWriter, sessionID string, devMode bool) {
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
