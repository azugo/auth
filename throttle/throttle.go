// Package throttle guards credential-checking endpoints against brute force.
package throttle

import (
	"context"
	"time"

	"azugo.io/auth/contract"

	"azugo.io/core/cache"
	"azugo.io/core/ratelimit"
)

// Throttle guards credential-checking endpoints. Implementations are keyed by a caller-chosen
// identity (IP, username, userID).
type Throttle interface {
	// Allow reports whether an attempt for key is permitted right now and, when blocked, how
	// long until the next attempt is allowed.
	Allow(ctx context.Context, key string) (ok bool, retryAfter time.Duration, err error)
	// Fail records a failed attempt.
	Fail(ctx context.Context, key string) error
	// Reset clears the counter after a successful attempt.
	Reset(ctx context.Context, key string) error
}

// New creates the default Throttle from configuration.
func New(c *cache.Cache, cfg contract.ThrottleConfig) (Throttle, error) {
	if !cfg.Enabled {
		return Noop(), nil
	}

	lim, err := ratelimit.NewFixedWindow(c, "auth:throttle", cfg.MaxAttempts, cfg.Window)
	if err != nil {
		return nil, err
	}

	return &limiterThrottle{lim: lim}, nil
}

type limiterThrottle struct {
	lim ratelimit.Limiter
}

// Allow reports whether an attempt for key is permitted right now.
func (t *limiterThrottle) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	res, err := t.lim.Peek(ctx, key)
	if err != nil {
		return false, 0, err
	}

	return res.Allowed, res.RetryAfter, nil
}

// Fail records a failed attempt.
func (t *limiterThrottle) Fail(ctx context.Context, key string) error {
	_, err := t.lim.Allow(ctx, key)

	return err
}

// Reset clears the counter after a successful attempt.
func (t *limiterThrottle) Reset(ctx context.Context, key string) error {
	return t.lim.Reset(ctx, key)
}

// Noop returns a Throttle that permits everything.
func Noop() Throttle {
	return noopThrottle{}
}

type noopThrottle struct{}

func (noopThrottle) Allow(context.Context, string) (bool, time.Duration, error) {
	return true, 0, nil
}

func (noopThrottle) Fail(context.Context, string) error {
	return nil
}

func (noopThrottle) Reset(context.Context, string) error {
	return nil
}
