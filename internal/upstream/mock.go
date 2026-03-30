package upstream

import (
	"context"
	"fmt"
)

// FakeProvider returns a hardcoded user without any HTTP calls. For unit tests only.
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

func (f *FakeProvider) AuthURL(state string) string {
	return "/fake-auth?state=" + state
}

func (f *FakeProvider) Exchange(_ context.Context, _ string) (*UserInfo, error) {
	if f.User == nil {
		return nil, fmt.Errorf("fake provider: no user configured")
	}
	return f.User, nil
}
