package service

import "testing"

func TestCheckAccess(t *testing.T) {
	tests := []struct {
		name    string
		status  string
		channel string
		want    AccessResult
	}{
		// active → all channels allowed
		{"active+browser", "active", "browser", AccessAllow},
		{"active+device", "active", "device", AccessAllow},
		{"active+mcp", "active", "mcp", AccessAllow},

		// pending_deletion → browser recovers, others denied
		{"pending+browser", "pending_deletion", "browser", AccessRecover},
		{"pending+device", "pending_deletion", "device", AccessDeny},
		{"pending+mcp", "pending_deletion", "mcp", AccessDeny},

		// disabled → all denied
		{"disabled+browser", "disabled", "browser", AccessDeny},
		{"disabled+device", "disabled", "device", AccessDeny},

		// deleted → all denied
		{"deleted+browser", "deleted", "browser", AccessDeny},
		{"deleted+mcp", "deleted", "mcp", AccessDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckAccess(tt.status, tt.channel)
			if got != tt.want {
				t.Errorf("CheckAccess(%q, %q) = %d, want %d", tt.status, tt.channel, got, tt.want)
			}
		})
	}
}

func TestIsActive(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{"active", true},
		{"pending_deletion", false},
		{"disabled", false},
		{"deleted", false},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			if got := IsActive(tt.status); got != tt.want {
				t.Errorf("IsActive(%q) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}
