package upstream

import (
	"net/http"
	"net/url"
)

// FakeProvider returns a hardcoded user without any HTTP calls. For unit tests only.
//
// It simulates an already-trusted exchange (no state-cookie or PKCE
// enforcement) so existing integration/unit tests keep working.
type FakeProvider struct {
	User         *UserInfo
	ProviderName string // defaults to "fake" if empty
}

func (f *FakeProvider) Name() string {
	if f.ProviderName != "" {
		return f.ProviderName
	}
	return "fake"
}

// Redirect points at /fake-auth with the state and, when set, the upstream
// prompt as query parameters so tests can read both from the Location header.
func (f *FakeProvider) Redirect(w http.ResponseWriter, r *http.Request, state string, opts ...RedirectOption) {
	query := url.Values{"state": {state}}
	if o := applyRedirectOptions(opts); o.prompt != "" {
		query.Set("prompt", o.prompt)
	}
	http.Redirect(w, r, "/fake-auth?"+query.Encode(), http.StatusFound)
}

func (f *FakeProvider) Callback(w http.ResponseWriter, r *http.Request, onSuccess func(w http.ResponseWriter, r *http.Request, state string, info *UserInfo)) {
	if f.User == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	state := r.URL.Query().Get("state")
	onSuccess(w, r, state, f.User)
}
