package service

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/kangheeyong/authgate/internal/storage"
)

// promptMode is what the OIDC prompt parameter (OIDC Core §3.1.2.1) of an auth
// request asks of the browser and mcp login channels.
type promptMode int

const (
	// promptDefault reuses a usable session and otherwise signs in upstream.
	// It covers no prompt and prompt=consent: authgate has no consent step.
	promptDefault promptMode = iota
	// promptSilent (prompt=none) reuses a usable session and otherwise ends
	// the request with login_required, without any page or upstream redirect.
	promptSilent
	// promptInteractive (prompt=login or select_account) never reuses a
	// session and sends the user upstream to pick an account.
	promptInteractive
)

// upstreamPromptSelectAccount is sent to the upstream IdP for prompt=login
// and prompt=select_account. Google does not accept prompt=login;
// select_account always shows its account chooser.
const upstreamPromptSelectAccount = "select_account"

func loginPromptMode(prompt []string) promptMode {
	mode := promptDefault
	for _, value := range prompt {
		switch value {
		case "none":
			// zitadel rejects none combined with any other value at /authorize.
			return promptSilent
		case "login", "select_account":
			mode = promptInteractive
		}
	}
	return mode
}

// loadLoginAuthRequest fetches the auth request a login URL names.
func loadLoginAuthRequest(ctx context.Context, store LoginStore, authRequestID string) (*storage.AuthRequestModel, *LoginResult) {
	authReq, err := store.GetAuthRequestModel(ctx, authRequestID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, &LoginResult{Action: ActionError, Error: "auth_request_not_found", ErrorCode: http.StatusBadRequest}
	}
	// An expired auth request is the client's stale link, not a server fault.
	var oerr *oidc.Error
	if errors.As(err, &oerr) {
		return nil, &LoginResult{Action: ActionError, Error: "auth_request_expired", ErrorCode: http.StatusBadRequest}
	}
	if err != nil {
		return nil, &LoginResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	return authReq, nil
}

func redirectToProviderSelectingAccount(authRequestID string) *LoginResult {
	return &LoginResult{Action: ActionRedirectToIdP, AuthRequestID: authRequestID, UpstreamPrompt: upstreamPromptSelectAccount}
}

// loginRequired ends a prompt=none request that has no usable session with an
// OIDC login_required authorization error sent to the client's redirect_uri
// (query response mode), carrying the request state and the RFC 9207 issuer.
// The redirect_uri was validated against the client when zitadel created the
// auth request. The channel binding is checked first so a request routed to
// the wrong login channel still gets the channel_mismatch page.
func loginRequired(ctx context.Context, store LoginStore, channel, issuer string, authReq *storage.AuthRequestModel, ipAddress, userAgent string) *LoginResult {
	if _, errMsg, code := verifyAuthRequestChannel(ctx, store, authReq, channel, ipAddress, userAgent, nil); errMsg != "" {
		return &LoginResult{Action: ActionError, Error: errMsg, ErrorCode: code}
	}
	target, err := url.Parse(authReq.RedirectURI)
	if err != nil || !target.IsAbs() {
		return &LoginResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	query := target.Query()
	query.Set("error", "login_required")
	if authReq.State != "" {
		query.Set("state", authReq.State)
	}
	query.Set("iss", issuer)
	target.RawQuery = query.Encode()
	return &LoginResult{Action: ActionRedirectToClient, AuthRequestID: authReq.ID, RedirectURL: target.String()}
}
