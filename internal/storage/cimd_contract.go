package storage

import (
	"context"
	"net/url"
	"strings"
)

// CIMDFetcher fetches and validates CIMD (Client ID Metadata Document) clients.
type CIMDFetcher interface {
	FetchClient(ctx context.Context, clientID string) (*ClientModel, error)
}

func isCIMDClientID(clientID string) bool {
	// ParseRequestURI doesn't parse fragments, check raw string
	if strings.Contains(clientID, "#") {
		return false
	}
	u, err := url.ParseRequestURI(clientID)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	if u.Host == "" || u.Hostname() == "" {
		return false
	}
	if u.User != nil {
		return false
	}
	if u.Path == "" || u.Path == "/" {
		return false
	}
	if u.RawQuery != "" {
		return false
	}
	return true
}

// IsCIMDClientID reports whether a client_id is a CIMD URL.
func IsCIMDClientID(clientID string) bool {
	return isCIMDClientID(clientID)
}
