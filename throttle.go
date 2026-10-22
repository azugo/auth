package auth

import (
	"context"
	"strings"

	"azugo.io/auth/event"
)

// checkThrottle claims an attempt on every key, refusing (and refunding the claims made so
// far) when any key is exhausted or locked out.
func (a *Auth) checkThrottle(ctx context.Context, keys []string, clientID, ip string) error {
	for i, key := range keys {
		ok, retryAfter, err := a.throttle.Allow(ctx, key)
		if err != nil {
			a.refundThrottle(ctx, keys[:i])

			return NewOAuthErrorFrom(err)
		}

		if !ok {
			a.refundThrottle(ctx, keys[:i])
			a.emit(ctx, event.Event{Type: event.TypeLockout, ClientID: clientID, IP: ip, Detail: map[string]any{"key": key}})

			return NewThrottledError(retryAfter)
		}
	}

	return nil
}

// refundThrottle returns the claims on every key when the attempt was not a guess.
func (a *Auth) refundThrottle(ctx context.Context, keys []string) {
	for _, key := range keys {
		_ = a.throttle.Refund(ctx, key)
	}
}

// passThrottle settles a successful attempt: identity is cleared and every other key refunded,
// so successes never count against a shared source.
func (a *Auth) passThrottle(ctx context.Context, keys []string, identity string) {
	for _, key := range keys {
		if key == identity {
			_ = a.throttle.Reset(ctx, key)
		} else {
			_ = a.throttle.Refund(ctx, key)
		}
	}
}

// failThrottle records a failed attempt on every key.
func (a *Auth) failThrottle(ctx context.Context, keys []string) {
	for _, key := range keys {
		_ = a.throttle.Fail(ctx, key)
	}
}

// resetThrottle clears every key after a successful attempt.
func (a *Auth) resetThrottle(ctx context.Context, keys []string) {
	for _, key := range keys {
		_ = a.throttle.Reset(ctx, key)
	}
}

func throttleIdentity(prefix, identifier string) string {
	return prefix + strings.ToLower(strings.TrimSpace(identifier))
}

// throttleKeys combines a stable identity key with the caller's IP.
func throttleKeys(identity, ip string) []string {
	keys := make([]string, 0, 2)

	if identity != "" {
		keys = append(keys, identity)
	}

	if ip != "" {
		keys = append(keys, "ip:"+ip)
	}

	return keys
}
