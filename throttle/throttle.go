// Package throttle guards credential-checking endpoints against brute force.
package throttle

import (
	"context"
	"time"

	"azugo.io/auth/contract"

	"azugo.io/core/cache"
)

// Throttle guards credential-checking endpoints. Implementations are keyed by a caller-chosen
// identity (IP, username, userID). Allow claims an attempt before the credential is checked,
// so concurrent requests cannot share one.
type Throttle interface {
	// Allow claims an attempt for key, reporting whether it is permitted right now and, when
	// blocked, how long until the next attempt is allowed.
	Allow(ctx context.Context, key string) (ok bool, retryAfter time.Duration, err error)
	// Fail keeps the claimed attempt as a failure, starting a lockout on the one that exhausts
	// the window.
	Fail(ctx context.Context, key string) error
	// Refund returns a claimed attempt that turned out not to be a guess.
	Refund(ctx context.Context, key string) error
	// Reset clears the counter and any lockout after a successful attempt.
	Reset(ctx context.Context, key string) error
}

// New creates the default Throttle over cfg, read live on every call.
func New(c *cache.Cache, cfg *contract.ThrottleConfig) (Throttle, error) {
	attempts, err := cache.CreateCounter(c, "auth:throttle")
	if err != nil {
		return nil, err
	}

	locks, err := cache.Create[bool](c, "auth:lockout")
	if err != nil {
		return nil, err
	}

	return &counterThrottle{attempts: attempts, locks: locks, limits: func() (int64, time.Duration, time.Duration) {
		if !cfg.Enabled {
			return 0, 0, 0
		}

		return int64(cfg.MaxAttempts), cfg.Window, cfg.LockoutTTL
	}}, nil
}

// NewLimit creates a Throttle with its own cache namespace and a fixed limit.
func NewLimit(c *cache.Cache, name string, limit int, window time.Duration) (Throttle, error) {
	if limit <= 0 {
		return Noop(), nil
	}

	attempts, err := cache.CreateCounter(c, name)
	if err != nil {
		return nil, err
	}

	return &counterThrottle{attempts: attempts, limits: func() (int64, time.Duration, time.Duration) { return int64(limit), window, 0 }}, nil
}

// counterThrottle counts claimed attempts per key in a fixed window that starts with the
// first claim.
type counterThrottle struct {
	attempts cache.Counter
	locks    cache.Instance[bool]
	// limits reports the current limit, window and lockout; a zero limit permits everything.
	limits func() (limit int64, window, lockout time.Duration)
}

// Allow claims an attempt for key.
func (t *counterThrottle) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	limit, window, lockout := t.limits()
	if limit <= 0 {
		return true, 0, nil
	}

	if t.locks != nil && lockout > 0 {
		// The entry's own expiry ends the lockout, so its remaining lifetime is the wait.
		remaining, locked, err := t.locks.TTL(ctx, key)
		if err != nil {
			return false, 0, err
		}

		if locked {
			return false, remaining, nil
		}
	}

	count, err := t.attempts.Increment(ctx, key, 1, cache.TTL[int64](window))
	if err != nil {
		return false, 0, err
	}

	if count <= limit {
		return true, 0, nil
	}

	if err := t.Refund(ctx, key); err != nil {
		return false, 0, err
	}

	remaining, _, err := t.attempts.TTL(ctx, key)
	if err != nil {
		return false, 0, err
	}

	if remaining <= 0 {
		remaining = window
	}

	return false, remaining, nil
}

// Fail keeps the claimed attempt, starting a lockout when it exhausted the window.
func (t *counterThrottle) Fail(ctx context.Context, key string) error {
	limit, _, lockout := t.limits()
	if t.locks == nil || limit <= 0 || lockout <= 0 {
		return nil
	}

	count, err := t.attempts.Get(ctx, key)
	if err != nil || count < limit {
		return err
	}

	if err := t.locks.Set(ctx, key, true, cache.TTL[bool](lockout)); err != nil {
		return err
	}

	return t.locks.Sync(ctx)
}

// Refund returns a claimed attempt.
func (t *counterThrottle) Refund(ctx context.Context, key string) error {
	count, err := t.attempts.Increment(ctx, key, -1)
	if err != nil || count > 0 {
		return err
	}

	return t.attempts.Delete(ctx, key)
}

// Reset clears the counter and any lockout after a successful attempt.
func (t *counterThrottle) Reset(ctx context.Context, key string) error {
	if t.locks != nil {
		if err := t.locks.Delete(ctx, key); err != nil {
			return err
		}

		if err := t.locks.Sync(ctx); err != nil {
			return err
		}
	}

	return t.attempts.Delete(ctx, key)
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

func (noopThrottle) Refund(context.Context, string) error {
	return nil
}

func (noopThrottle) Reset(context.Context, string) error {
	return nil
}
