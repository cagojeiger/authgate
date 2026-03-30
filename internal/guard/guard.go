package guard

import "time"

// LoginState is the derived login state for a user.
type LoginState int

const (
	Inactive                     LoginState = iota // disabled or deleted
	RecoverableBrowserOnly                         // pending_deletion
	InitialOnboardingIncomplete                    // terms/privacy not accepted yet
	ReconsentRequired                              // accepted but version mismatch
	OnboardingComplete                             // fully ready
)

func (s LoginState) String() string {
	switch s {
	case Inactive:
		return "inactive"
	case RecoverableBrowserOnly:
		return "recoverable_browser_only"
	case InitialOnboardingIncomplete:
		return "initial_onboarding_incomplete"
	case ReconsentRequired:
		return "reconsent_required"
	case OnboardingComplete:
		return "onboarding_complete"
	default:
		return "unknown"
	}
}

// Channel represents a login channel.
type Channel int

const (
	ChannelBrowser Channel = iota
	ChannelDevice
	ChannelMCP
	ChannelRefresh
)

// GuardResult is the outcome of GuardLoginChannel.
type GuardResult int

const (
	Allow              GuardResult = iota
	AccountInactive                // 403 account_inactive
	RecoverThenContinue            // browser-only recovery
	ShowTerms                      // browser shows terms page
	SignupRequired                 // 403 signup_required
)

func (r GuardResult) String() string {
	switch r {
	case Allow:
		return "allow"
	case AccountInactive:
		return "account_inactive"
	case RecoverThenContinue:
		return "recover_then_continue"
	case ShowTerms:
		return "show_terms"
	case SignupRequired:
		return "signup_required"
	default:
		return "unknown"
	}
}

// UserInfo holds the fields needed for DeriveLoginState.
// This is not a DB model — it's the minimal set of fields for guard logic.
type UserInfo struct {
	Status            string
	TermsAcceptedAt   *time.Time
	PrivacyAcceptedAt *time.Time
	TermsVersion      string
	PrivacyVersion    string
}

// DeriveLoginState computes the login state from user fields and current config versions.
// Pure function — no DB, no HTTP.
func DeriveLoginState(user *UserInfo, currentTermsVersion, currentPrivacyVersion string) LoginState {
	// 1. disabled or deleted → inactive
	if user.Status == "disabled" || user.Status == "deleted" {
		return Inactive
	}

	// 2. pending_deletion → recoverable (browser only)
	if user.Status == "pending_deletion" {
		return RecoverableBrowserOnly
	}

	// 3. terms or privacy never accepted → initial onboarding incomplete
	if user.TermsAcceptedAt == nil || user.PrivacyAcceptedAt == nil {
		return InitialOnboardingIncomplete
	}

	// 4. version mismatch → reconsent required
	if user.TermsVersion != currentTermsVersion || user.PrivacyVersion != currentPrivacyVersion {
		return ReconsentRequired
	}

	// 5. all good
	return OnboardingComplete
}

// GuardLoginChannel determines what action to take based on login state and channel.
// Pure function — no DB, no HTTP.
func GuardLoginChannel(user *UserInfo, channel Channel, currentTermsVersion, currentPrivacyVersion string) GuardResult {
	state := DeriveLoginState(user, currentTermsVersion, currentPrivacyVersion)

	switch state {
	case Inactive:
		return AccountInactive

	case RecoverableBrowserOnly:
		if channel == ChannelBrowser {
			return RecoverThenContinue
		}
		return AccountInactive

	case InitialOnboardingIncomplete, ReconsentRequired:
		if channel == ChannelBrowser {
			return ShowTerms
		}
		return SignupRequired

	case OnboardingComplete:
		return Allow
	}

	return AccountInactive // unreachable
}
