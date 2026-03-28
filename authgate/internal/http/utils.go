package http

import (
	"authgate/internal/domain"
)

func generateCode() string {
	return domain.GenerateCode()
}

func generateState(originalState, clientID, redirectURI, scope, challenge, nonce string) string {
	return domain.GenerateState(originalState, clientID, redirectURI, scope, challenge, nonce)
}

func parseState(state string) (originalState, clientID, redirectURI, scope, challenge, nonce string) {
	data := domain.ParseState(state)
	return data.OriginalReq, data.ClientID, data.RedirectURI, data.Scope, data.Challenge, data.Nonce
}
