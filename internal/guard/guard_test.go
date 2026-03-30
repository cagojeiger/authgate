package guard

import (
	"testing"
	"time"
)

func ptr(t time.Time) *time.Time { return &t }

var now = time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)

func TestDeriveLoginState(t *testing.T) {
	const termsV = "2026-03-28"
	const privacyV = "2026-03-28"

	tests := []struct {
		id   string
		user UserInfo
		want LoginState
	}{
		{"state-001", UserInfo{Status: "disabled"}, Inactive},
		{"state-002", UserInfo{Status: "deleted"}, Inactive},
		{"state-003", UserInfo{Status: "pending_deletion"}, RecoverableBrowserOnly},
		{"state-004", UserInfo{Status: "active", TermsAcceptedAt: nil, PrivacyAcceptedAt: ptr(now)}, InitialOnboardingIncomplete},
		{"state-005", UserInfo{Status: "active", TermsAcceptedAt: ptr(now), PrivacyAcceptedAt: nil}, InitialOnboardingIncomplete},
		{"state-006", UserInfo{Status: "active", TermsAcceptedAt: ptr(now), PrivacyAcceptedAt: ptr(now), TermsVersion: "2025-01-01", PrivacyVersion: privacyV}, ReconsentRequired},
		{"state-007", UserInfo{Status: "active", TermsAcceptedAt: ptr(now), PrivacyAcceptedAt: ptr(now), TermsVersion: termsV, PrivacyVersion: "2025-01-01"}, ReconsentRequired},
		{"state-008", UserInfo{Status: "active", TermsAcceptedAt: ptr(now), PrivacyAcceptedAt: ptr(now), TermsVersion: termsV, PrivacyVersion: privacyV}, OnboardingComplete},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := DeriveLoginState(&tt.user, termsV, privacyV)
			if got != tt.want {
				t.Errorf("DeriveLoginState() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGuardLoginChannel(t *testing.T) {
	const termsV = "2026-03-28"
	const privacyV = "2026-03-28"

	inactive := UserInfo{Status: "disabled"}
	recoverable := UserInfo{Status: "pending_deletion"}
	incomplete := UserInfo{Status: "active", TermsAcceptedAt: nil}
	reconsent := UserInfo{Status: "active", TermsAcceptedAt: ptr(now), PrivacyAcceptedAt: ptr(now), TermsVersion: "old", PrivacyVersion: privacyV}
	complete := UserInfo{Status: "active", TermsAcceptedAt: ptr(now), PrivacyAcceptedAt: ptr(now), TermsVersion: termsV, PrivacyVersion: privacyV}

	tests := []struct {
		id      string
		user    UserInfo
		channel Channel
		want    GuardResult
	}{
		{"guard-001", inactive, ChannelBrowser, AccountInactive},
		{"guard-002", inactive, ChannelDevice, AccountInactive},
		{"guard-003", recoverable, ChannelBrowser, RecoverThenContinue},
		{"guard-004", recoverable, ChannelDevice, AccountInactive},
		{"guard-005", incomplete, ChannelBrowser, ShowTerms},
		{"guard-006", incomplete, ChannelMCP, SignupRequired},
		{"guard-007", reconsent, ChannelBrowser, ShowTerms},
		{"guard-008", reconsent, ChannelRefresh, SignupRequired},
		{"guard-009", complete, ChannelBrowser, Allow},
		{"guard-010", complete, ChannelDevice, Allow},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := GuardLoginChannel(&tt.user, tt.channel, termsV, privacyV)
			if got != tt.want {
				t.Errorf("GuardLoginChannel() = %v, want %v", got, tt.want)
			}
		})
	}
}
