package service

// AccessResult describes what action to take based on user status and channel.
type AccessResult int

const (
	AccessAllow    AccessResult = iota // Proceed normally
	AccessRecover                      // Browser-only: recover from pending_deletion, then proceed
	AccessDeny                         // Reject with 403
)

// CheckAccess is a pure function that determines access based on user status and channel.
// This is the single source of truth for the status × channel matrix.
//
//	status\channel | browser | device | mcp
//	─────────────────────────────────────────
//	active         | Allow   | Allow  | Allow
//	pending_deletion| Recover | Deny   | Deny
//	disabled       | Deny    | Deny   | Deny
//	deleted        | Deny    | Deny   | Deny
func CheckAccess(status, channel string) AccessResult {
	switch status {
	case "disabled", "deleted":
		return AccessDeny
	case "pending_deletion":
		if channel == "browser" {
			return AccessRecover
		}
		return AccessDeny
	default: // active
		return AccessAllow
	}
}

// IsActive is a pure function for token-level status checks (refresh, code exchange).
// Only active users can exchange/refresh tokens.
func IsActive(status string) bool {
	return status == "active"
}
