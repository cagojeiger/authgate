package upstream

import "net/http"

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

func (f *FakeProvider) Redirect(w http.ResponseWriter, r *http.Request, state string) {
	http.Redirect(w, r, "/fake-auth?state="+state, http.StatusFound)
}

func (f *FakeProvider) Callback(w http.ResponseWriter, r *http.Request, onSuccess func(w http.ResponseWriter, r *http.Request, state string, info *UserInfo)) {
	if f.User == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	state := r.URL.Query().Get("state")
	onSuccess(w, r, state, f.User)
}
