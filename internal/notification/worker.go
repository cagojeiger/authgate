package notification

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

const weeklyReportType = "weekly"

type WorkerConfig struct {
	OutboxEnabled        bool
	WeeklyReportEnabled  bool
	Interval             time.Duration
	BatchSize            int
	RetryBaseDelay       time.Duration
	ReportWeekday        time.Weekday
	ReportHour           int
	ReportLocation       *time.Location
	ReportLookback       time.Duration
	InterMessageInterval time.Duration
}

type Worker struct {
	store  *Store
	slack  *SlackClient
	config WorkerConfig
}

func NewWorker(store *Store, slack *SlackClient, cfg WorkerConfig) *Worker {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 20
	}
	if cfg.RetryBaseDelay <= 0 {
		cfg.RetryBaseDelay = time.Minute
	}
	if cfg.ReportLocation == nil {
		cfg.ReportLocation = time.UTC
	}
	if cfg.ReportLookback <= 0 {
		cfg.ReportLookback = 7 * 24 * time.Hour
	}
	if cfg.InterMessageInterval <= 0 {
		cfg.InterMessageInterval = time.Second
	}
	return &Worker{store: store, slack: slack, config: cfg}
}

func (w *Worker) Start(ctx context.Context) {
	w.run(ctx)

	ticker := time.NewTicker(w.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("notification worker stopped")
			return
		case <-ticker.C:
			w.run(ctx)
		}
	}
}

func (w *Worker) run(ctx context.Context) {
	if !w.config.OutboxEnabled && !w.config.WeeklyReportEnabled {
		return
	}
	if acquired, err := w.store.WithWorkerLock(ctx, func(ctx context.Context) error {
		var runErr error
		if w.config.OutboxEnabled {
			if err := w.processOutbox(ctx); err != nil {
				runErr = errors.Join(runErr, err)
			}
		}
		if w.config.WeeklyReportEnabled {
			if err := w.processWeeklyReport(ctx); err != nil {
				runErr = errors.Join(runErr, err)
			}
		}
		return runErr
	}); err != nil {
		slog.ErrorContext(ctx, "notification worker run failed", "error", err)
	} else if !acquired {
		slog.DebugContext(ctx, "notification worker skipped: advisory lock not acquired")
	}
}

func (w *Worker) processOutbox(ctx context.Context) error {
	events, err := w.store.PendingOutboxEvents(ctx, w.config.BatchSize)
	if err != nil {
		return err
	}
	for i, event := range events {
		if err := w.slack.Post(ctx, FormatOutboxEvent(event)); err != nil {
			nextAttempt := w.nextAttemptAt(event.AttemptCount, err)
			if markErr := w.store.MarkOutboxFailed(ctx, event.ID, nextAttempt, err); markErr != nil {
				return errors.Join(err, markErr)
			}
			continue
		}
		if err := w.store.MarkOutboxSent(ctx, event.ID); err != nil {
			return err
		}
		if i < len(events)-1 {
			if err := sleepContext(ctx, w.config.InterMessageInterval); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *Worker) processWeeklyReport(ctx context.Context) error {
	periodEnd := LatestReportEnd(w.store.clock.Now(), w.config.ReportWeekday, w.config.ReportHour, w.config.ReportLocation)
	periodStart := periodEnd.Add(-w.config.ReportLookback)

	runID, claimed, err := w.store.ClaimReportRun(ctx, weeklyReportType, periodStart, periodEnd)
	if err != nil {
		return err
	}
	if !claimed {
		return nil
	}

	summary, err := w.store.WeeklySummary(ctx, periodStart, periodEnd)
	if err != nil {
		_ = w.store.MarkReportFailed(ctx, runID, err)
		return err
	}
	if err := w.slack.Post(ctx, FormatWeeklyReport(periodStart, periodEnd, summary)); err != nil {
		if markErr := w.store.MarkReportFailed(ctx, runID, err); markErr != nil {
			return errors.Join(err, markErr)
		}
		return err
	}
	return w.store.MarkReportSent(ctx, runID)
}

func (w *Worker) nextAttemptAt(attemptCount int, err error) time.Time {
	if rateLimited := (&RateLimitError{}); errors.As(err, &rateLimited) {
		return w.store.clock.Now().Add(rateLimited.RetryAfter)
	}
	multiplier := 1 << min(attemptCount, 5)
	return w.store.clock.Now().Add(time.Duration(multiplier) * w.config.RetryBaseDelay)
}

func LatestReportEnd(now time.Time, weekday time.Weekday, hour int, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	localNow := now.In(loc)
	y, m, d := localNow.Date()
	candidate := time.Date(y, m, d, hour, 0, 0, 0, loc)
	daysSince := (int(localNow.Weekday()) - int(weekday) + 7) % 7
	candidate = candidate.AddDate(0, 0, -daysSince)
	if candidate.After(localNow) {
		candidate = candidate.AddDate(0, 0, -7)
	}
	return candidate.UTC()
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
