//go:build integration

package integration

import (
	"net/http"
	"testing"
)

func TestIntegration_Discovery(t *testing.T) {
	ts := SetupTestServer(t)

	resp, err := http.Get(ts.BaseURL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("discovery status = %d, want 200", resp.StatusCode)
	}
}

// device-008: consumed device code re-polling → error
