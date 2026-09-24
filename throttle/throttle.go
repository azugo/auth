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

	t, err := NewLimit(c, "auth:throttle", cfg.MaxAttempts, cfg.Window)
	if err != nil || cfg.LockoutTTL <= 0 {
		return t, err
	}

	lt, ok := t.(*limiterThrottle)
	if !ok {
		return t, nil
	}

	locks, err := cache.Create[bool](c, "auth:lockout")
	if err != nil {
		return nil, err
	}

	lt.locks = locks
	lt.lockout = cfg.LockoutTTL

	return lt, nil
}

// NewLimit creates a Throttle with its own cache namespace and limit.
func NewLimit(c *cache.Cache, name string, limit int, window time.Duration) (Throttle, error) {
	if limit <= 0 {
		return Noop(), nil
	}

	lim, err := ratelimit.NewFixedWindow(c, name, limit, window)
	if err != nil {
		return nil, err
	}

	return &limiterThrottle{lim: lim}, nil
}

type limiterThrottle struct {
	lim     ratelimit.Limiter
	locks   cache.Instance[bool]
	lockout time.Duration
}

// Allow reports whether an attempt for key is permitted right now.
func (t *limiterThrottle) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	if t.locks != nil {
		// The entry's own expiry ends the lockout, so its remaining lifetime is the wait.
		remaining, locked, err := t.locks.TTL(ctx, key)
		if err != nil {
			return false, 0, err
		}

		if locked {
			return false, remaining, nil
		}
	}

	res, err := t.lim.Peek(ctx, key)
	if err != nil {
		return false, 0, err
	}

	return res.Allowed, res.RetryAfter, nil
}

// Fail records a failed attempt, starting a lockout on the one that exhausts the window.
func (t *limiterThrottle) Fail(ctx context.Context, key string) error {
	res, err := t.lim.Allow(ctx, key)
	if err != nil || t.locks == nil || res.Remaining > 0 {
		return err
	}

	if err := t.locks.Set(ctx, key, true, cache.TTL[bool](t.lockout)); err != nil {
		return err
	}

	return t.locks.Sync(ctx)
}

// Reset clears the counter and any lockout after a successful attempt.
func (t *limiterThrottle) Reset(ctx context.Context, key string) error {
	if t.locks != nil {
		if err := t.locks.Delete(ctx, key); err != nil {
			return err
		}

		if err := t.locks.Sync(ctx); err != nil {
			return err
		}
	}

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
