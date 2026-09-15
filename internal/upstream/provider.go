package upstream

import "net/http"

// UserInfo holds identity data returned from the upstream IdP.
type UserInfo struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
	// HostedDomain is the Google Workspace domain (the hd claim) the account
	// belongs to; empty for consumer accounts and IdPs that do not send one.
	HostedDomain string
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
	// when enabled). opts adjust the upstream authorization request.
	Redirect(w http.ResponseWriter, r *http.Request, state string, opts ...RedirectOption)

	// Callback verifies the state cookie + PKCE, exchanges the authorization
	// code, fetches userinfo, and invokes onSuccess with the resolved state and
	// user identity. On verification or exchange failure it writes its own
	// error response and does not call onSuccess.
	Callback(w http.ResponseWriter, r *http.Request, onSuccess func(w http.ResponseWriter, r *http.Request, state string, info *UserInfo))
}

// RedirectOption adjusts one upstream authorization request.
type RedirectOption func(*redirectOptions)

type redirectOptions struct {
	prompt string
}

// WithPrompt sends prompt as the upstream OIDC prompt parameter. Google
// accepts none, consent and select_account.
func WithPrompt(prompt string) RedirectOption {
	return func(o *redirectOptions) { o.prompt = prompt }
}

func applyRedirectOptions(opts []RedirectOption) redirectOptions {
	var o redirectOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
