package cmd

import (
	"context"
	"time"
)

// rateLimiter paces requests to the KDC using a shared ticker so that all
// worker threads combined never exceed the configured requests per second.
type rateLimiter struct {
	ticker *time.Ticker
}

var limiter *rateLimiter

func newRateLimiter(requestsPerSecond int) *rateLimiter {
	if requestsPerSecond <= 0 {
		return nil
	}
	interval := time.Second / time.Duration(requestsPerSecond)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	return &rateLimiter{ticker: time.NewTicker(interval)}
}

// wait blocks until the next rate limit token is available. It returns false
// if the context is cancelled while waiting.
func (r *rateLimiter) wait(ctx context.Context) bool {
	if r == nil {
		return true
	}
	select {
	case <-ctx.Done():
		return false
	case <-r.ticker.C:
		return true
	}
}
