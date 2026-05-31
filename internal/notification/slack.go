package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

type SlackClient struct {
	webhookURL string
	client     *http.Client
}

type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("slack rate limited; retry after %s", e.RetryAfter)
}

func NewSlackClient(webhookURL string, client *http.Client) *SlackClient {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &SlackClient{webhookURL: webhookURL, client: client}
}

func (c *SlackClient) Post(ctx context.Context, text string) error {
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return &RateLimitError{RetryAfter: retryAfter(resp.Header.Get("Retry-After"))}
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("slack webhook returned %d: %s", resp.StatusCode, string(raw))
}

func retryAfter(v string) time.Duration {
	seconds, err := strconv.Atoi(v)
	if err != nil || seconds < 1 {
		return time.Minute
	}
	return time.Duration(seconds) * time.Second
}
