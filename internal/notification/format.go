package notification

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

func FormatOutboxEvent(event OutboxEvent) string {
	switch event.EventType {
	case "auth.signup":
		return fmt.Sprintf("Authgate signup\nuser_id: %s\nclient: %s", emptyDash(event.UserID), clientLabel(event.Metadata))
	case "auth.deletion_requested":
		return fmt.Sprintf("Authgate account deletion requested\nuser_id: %s\nclient: %s", emptyDash(event.UserID), clientLabel(event.Metadata))
	case "auth.refresh_reuse_detected":
		return fmt.Sprintf("Authgate security alert: refresh token reuse detected\nuser_id: %s\nfamily_id: %s\nrelated refresh token family was revoked by authgate", emptyDash(event.UserID), metadataString(event.Metadata, "family_id"))
	default:
		return fmt.Sprintf("Authgate audit event\n event_type: %s\nuser_id: %s", event.EventType, emptyDash(event.UserID))
	}
}

func FormatWeeklyReport(periodStart, periodEnd time.Time, summary Summary) string {
	loginTotal := int64(0)
	channels := make([]string, 0, len(summary.LoginByChannel))
	for channel, count := range summary.LoginByChannel {
		loginTotal += count
		channels = append(channels, channel)
	}
	sort.Strings(channels)

	var loginLines []string
	for _, channel := range channels {
		loginLines = append(loginLines, fmt.Sprintf("  - %s: %d", channel, summary.LoginByChannel[channel]))
	}
	if len(loginLines) == 0 {
		loginLines = append(loginLines, "  - none: 0")
	}

	return fmt.Sprintf(`Authgate weekly report
period: %s - %s

Users
- total: %d
- active: %d

Events
- signups: %d
- deletion requested: %d
- deletion completed: %d

Logins
- total: %d
%s

Security
- refresh token reuse detected: %d
- channel mismatch: %d`,
		periodStart.Format(time.RFC3339),
		periodEnd.Format(time.RFC3339),
		summary.TotalUsers,
		summary.ActiveUsers,
		summary.SignupCount,
		summary.DeletionRequested,
		summary.DeletionCompleted,
		loginTotal,
		strings.Join(loginLines, "\n"),
		summary.RefreshReuse,
		summary.ChannelMismatch,
	)
}

func clientLabel(metadata map[string]any) string {
	name := metadataString(metadata, "client_name")
	id := metadataString(metadata, "client_id")
	switch {
	case name != "-" && id != "-":
		return name + " (" + id + ")"
	case name != "-":
		return name
	default:
		return id
	}
}

func metadataString(metadata map[string]any, key string) string {
	if len(metadata) == 0 {
		return "-"
	}
	v, ok := metadata[key]
	if !ok || v == nil {
		return "-"
	}
	s := fmt.Sprint(v)
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func emptyDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}
