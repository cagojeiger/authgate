package domain

import (
	"encoding/base64"
	"strings"
	"time"
)

// StateData holds the parsed components of a state parameter.
type StateData struct {
	Timestamp   time.Time
	OriginalReq string
	ClientID    string
	RedirectURI string
	Scope       string
	Challenge   string
	Nonce       string
}

// GenerateState creates an opaque state parameter for OAuth flows.
// The state is base64-encoded and contains the original request data.
// This function is NOT pure - it includes a timestamp.
func GenerateState(originalReq, clientID, redirectURI, scope, challenge, nonce string) string {
	parts := []string{
		time.Now().Format(time.RFC3339Nano),
		originalReq,
		clientID,
		redirectURI,
		scope,
		challenge,
		nonce,
	}
	data := strings.Join(parts, "|")
	return base64.URLEncoding.EncodeToString([]byte(data))
}

// ParseState decodes and parses a state parameter.
// Returns empty strings if the state is invalid or malformed.
// This function is pure - it only transforms input data.
func ParseState(state string) StateData {
	data, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		return StateData{}
	}

	parts := strings.Split(string(data), "|")
	if len(parts) < 7 {
		return StateData{}
	}

	ts, _ := time.Parse(time.RFC3339Nano, parts[0])

	return StateData{
		Timestamp:   ts,
		OriginalReq: parts[1],
		ClientID:    parts[2],
		RedirectURI: parts[3],
		Scope:       parts[4],
		Challenge:   parts[5],
		Nonce:       parts[6],
	}
}
