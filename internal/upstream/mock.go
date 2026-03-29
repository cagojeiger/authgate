package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type MockProvider struct {
	idpURL       string
	idpPublicURL string
}

func NewMockProvider(idpURL, idpPublicURL string) *MockProvider {
	return &MockProvider{idpURL: idpURL, idpPublicURL: idpPublicURL}
}

func (p *MockProvider) AuthURL(state string) string {
	return fmt.Sprintf("%s/authorize?state=%s&redirect_uri=%s",
		p.idpPublicURL, state, url.QueryEscape(p.idpURL+"/callback"))
}

func (p *MockProvider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
	data := url.Values{"code": {code}, "grant_type": {"authorization_code"}}
	resp, err := http.PostForm(p.idpURL+"/token", data)
	if err != nil {
		return nil, fmt.Errorf("mock-idp exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mock-idp returned %d", resp.StatusCode)
	}

	var result struct {
		UserInfo struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
			Picture       string `json:"picture"`
		} `json:"user_info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode mock response: %w", err)
	}

	return &UserInfo{
		ProviderUserID: result.UserInfo.Sub,
		Email:          result.UserInfo.Email,
		EmailVerified:  result.UserInfo.EmailVerified,
		Name:           result.UserInfo.Name,
		Picture:        result.UserInfo.Picture,
	}, nil
}
