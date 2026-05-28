package upstream

import "net/http"

// UserInfo holds identity data returned from the upstream IdP.
type UserInfo struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
}

// Provider abstracts the upstream OIDC IdP.
//
// Redirect and Callback own the (w, r) pair so the underlying library's
// high-level handlers can manage the state cookie (CSRF) and PKCE challenge
// cookie. The service layer stays HTTP-agnostic and receives the already
// exchanged *UserInfo via the onSuccess callback.
type Provider interface {
	// Name returns the provider identifier stored in user_identities.provider.
	Name() string

	// Redirect sends the user to the upstream IdP authorization endpoint,
	// binding the given state value to a CSRF cookie (and PKCE challenge cookie
	// when enabled).
	Redirect(w http.ResponseWriter, r *http.Request, state string)

	// Callback verifies the state cookie + PKCE, exchanges the authorization
	// code, fetches userinfo, and invokes onSuccess with the resolved state and
	// user identity. On verification or exchange failure it writes its own
	// error response and does not call onSuccess.
	Callback(w http.ResponseWriter, r *http.Request, onSuccess func(w http.ResponseWriter, r *http.Request, state string, info *UserInfo))
}
