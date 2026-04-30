package middleware

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/kangheeyong/authgate/internal/clientinfo"
)

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter holds per-IP token bucket limiters.
type RateLimiter struct {
	mu      sync.Mutex
	ips     map[string]*ipLimiter
	r       rate.Limit
	b       int
	cleanup *time.Ticker
	done    chan struct{}
}

// NewRateLimiter returns an http middleware that enforces per-IP rate limiting
// using a token bucket with rate r (tokens/sec) and burst b.
func NewRateLimiter(r rate.Limit, b int) func(http.Handler) http.Handler {
	rl := &RateLimiter{
		ips:  make(map[string]*ipLimiter),
		r:    r,
		b:    b,
		done: make(chan struct{}),
	}
	rl.cleanup = time.NewTicker(5 * time.Minute)
	go rl.cleanupLoop()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ip := clientinfo.FromContext(req.Context()).IP
			if ip == "" {
				// Fall back to RemoteAddr host if clientinfo middleware was not
				// installed (test or partially-configured deployment). This
				// preserves limit behavior at the cost of one parse on miss.
				ip = req.RemoteAddr
			}
			if !rl.allow(ip) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":             "rate_limit_exceeded",
					"error_description": "too many requests",
				})
				return
			}
			next.ServeHTTP(w, req)
		})
	}
}

func (rl *RateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	l, ok := rl.ips[ip]
	if !ok {
		l = &ipLimiter{limiter: rate.NewLimiter(rl.r, rl.b)}
		rl.ips[ip] = l
	}
	l.lastSeen = time.Now()
	return l.limiter.Allow()
}

func (rl *RateLimiter) cleanupLoop() {
	for {
		select {
		case <-rl.cleanup.C:
			rl.evict(10 * time.Minute)
		case <-rl.done:
			rl.cleanup.Stop()
			return
		}
	}
}

func (rl *RateLimiter) evict(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for ip, l := range rl.ips {
		if l.lastSeen.Before(cutoff) {
			delete(rl.ips, ip)
		}
	}
}

