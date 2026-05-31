package notification

import (
	"strings"
	"testing"
	"time"
)

func TestFormatOutboxEvent_RefreshReuseMentionsFamilyRevoked(t *testing.T) {
	msg := FormatOutboxEvent(OutboxEvent{
		UserID:    "user-1",
		EventType: "auth.refresh_reuse_detected",
		Metadata:  map[string]any{"family_id": "family-1"},
	})

	for _, want := range []string{"refresh token reuse detected", "family-1", "family was revoked"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message = %q, want substring %q", msg, want)
		}
	}
}

func TestLatestReportEnd(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Seoul")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 6, 3, 12, 0, 0, 0, loc)
	got := LatestReportEnd(now, time.Monday, 9, loc)
	want := time.Date(2026, 6, 1, 9, 0, 0, 0, loc).UTC()
	if !got.Equal(want) {
		t.Fatalf("LatestReportEnd = %s, want %s", got, want)
	}

	beforeThisWeekSchedule := time.Date(2026, 6, 1, 8, 59, 0, 0, loc)
	got = LatestReportEnd(beforeThisWeekSchedule, time.Monday, 9, loc)
	want = time.Date(2026, 5, 25, 9, 0, 0, 0, loc).UTC()
	if !got.Equal(want) {
		t.Fatalf("LatestReportEnd before schedule = %s, want %s", got, want)
	}
}
