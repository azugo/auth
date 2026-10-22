package auth

import (
	"context"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"

	"github.com/go-quicktest/qt"
)

func TestPassThrottleClearsTheNamedIdentity(t *testing.T) {
	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a := newGrantsTestAuth(t, cfg, nil, mfaClient(client.MFAPolicyDisabled))
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(a.checkThrottle(ctx, []string{"id"}, "", "")))
	a.failThrottle(ctx, []string{"id"})

	// The identity is cleared wherever it sits among the keys.
	keys := []string{"ip:192.0.2.1", "id"}
	qt.Assert(t, qt.IsNil(a.checkThrottle(ctx, keys, "", "")))
	a.passThrottle(ctx, keys, "id")

	for range 2 {
		qt.Check(t, qt.IsNil(a.checkThrottle(ctx, []string{"id"}, "", "")))
	}
}
