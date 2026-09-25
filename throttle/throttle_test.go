package throttle

import (
	"context"
	"sync"
	"testing"
	"time"

	"azugo.io/auth/contract"

	"azugo.io/core/cache"
	"github.com/go-quicktest/qt"
)

func newCache(t *testing.T) *cache.Cache {
	t.Helper()

	c := cache.New(cache.MemoryCache)
	qt.Assert(t, qt.IsNil(c.Start(context.Background())))
	t.Cleanup(c.Close)

	return c
}

// fail claims an attempt and records it as failed.
func fail(t *testing.T, th Throttle, key string) {
	t.Helper()

	_, _, err := th.Allow(context.Background(), key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(th.Fail(context.Background(), key)))
}

func TestAllowClaimsAcrossConcurrentRequests(t *testing.T) {
	th, err := New(newCache(t), contract.ThrottleConfig{
		Enabled: true, MaxAttempts: 5, Window: time.Minute, LockoutTTL: time.Minute,
	})
	qt.Assert(t, qt.IsNil(err))

	results := make(chan bool, 50)

	var wg sync.WaitGroup

	for range 50 {
		wg.Go(func() {
			ok, _, err := th.Allow(context.Background(), "k")
			qt.Check(t, qt.IsNil(err))
			results <- ok
		})
	}

	wg.Wait()
	close(results)

	allowed := 0

	for ok := range results {
		if ok {
			allowed++
		}
	}

	// Every claim lands before any is settled, so only the budget gets through.
	qt.Check(t, qt.Equals(allowed, 5))
}

func TestRefundReturnsTheClaim(t *testing.T) {
	th, err := New(newCache(t), contract.ThrottleConfig{
		Enabled: true, MaxAttempts: 1, Window: time.Minute, LockoutTTL: time.Minute,
	})
	qt.Assert(t, qt.IsNil(err))

	ctx := context.Background()

	ok, _, err := th.Allow(ctx, "k")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.IsNil(th.Refund(ctx, "k")))

	// The refunded claim never counted, so the next one is allowed and only its failure
	// exhausts the window.
	ok, _, err = th.Allow(ctx, "k")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.IsNil(th.Fail(ctx, "k")))

	ok, _, err = th.Allow(ctx, "k")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(ok))
}

func TestDisabledPermitsEverything(t *testing.T) {
	th, err := New(newCache(t), contract.ThrottleConfig{})
	qt.Assert(t, qt.IsNil(err))

	for range 10 {
		_, _, err := th.Allow(context.Background(), "k")
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsNil(th.Fail(context.Background(), "k")))
	}

	ok, _, err := th.Allow(context.Background(), "k")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(ok))
}

func TestWindowBlocksAfterMaxAttempts(t *testing.T) {
	th, err := New(newCache(t), contract.ThrottleConfig{
		Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute,
	})
	qt.Assert(t, qt.IsNil(err))

	ctx := context.Background()

	for range 2 {
		ok, _, err := th.Allow(ctx, "k")
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsTrue(ok))
		qt.Assert(t, qt.IsNil(th.Fail(ctx, "k")))
	}

	ok, _, err := th.Allow(ctx, "k")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(ok))

	// A success clears the key.
	qt.Assert(t, qt.IsNil(th.Reset(ctx, "k")))

	ok, _, err = th.Allow(ctx, "k")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(ok))
}

func TestLockoutOutlivesTheWindow(t *testing.T) {
	th, err := New(newCache(t), contract.ThrottleConfig{
		Enabled: true, MaxAttempts: 2, Window: 50 * time.Millisecond, LockoutTTL: time.Hour,
	})
	qt.Assert(t, qt.IsNil(err))

	ctx := context.Background()

	for range 3 {
		fail(t, th, "k")
	}

	// The counting window has rolled over, but the lockout has not.
	time.Sleep(80 * time.Millisecond)

	ok, retryAfter, err := th.Allow(ctx, "k")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(ok))
	// The wait is what the lockout has left, close to but under the full hour.
	qt.Check(t, qt.IsTrue(retryAfter > 59*time.Minute && retryAfter <= time.Hour), qt.Commentf("got %s", retryAfter))

	// Another key is unaffected.
	ok, _, err = th.Allow(ctx, "other")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(ok))

	// A reset ends the lockout.
	qt.Assert(t, qt.IsNil(th.Reset(ctx, "k")))

	ok, _, err = th.Allow(ctx, "k")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(ok))
}

func TestLockoutBlocksTheWindowBoundaryBurst(t *testing.T) {
	// A lockout equal to the window is not redundant: the window blocks only for whatever
	// remains of it, so a key spent near the boundary would otherwise get a fresh budget at
	// once. The lockout blocks for a fixed period measured from the trip instead.
	th, err := New(newCache(t), contract.ThrottleConfig{
		Enabled: true, MaxAttempts: 2, Window: 200 * time.Millisecond, LockoutTTL: 200 * time.Millisecond,
	})
	qt.Assert(t, qt.IsNil(err))

	ctx := context.Background()

	// Open the window with one failure, then spend the rest just before it rolls over.
	fail(t, th, "k")
	time.Sleep(180 * time.Millisecond)
	fail(t, th, "k")

	// The window has rolled over, but the lockout started at the trip and has not.
	time.Sleep(40 * time.Millisecond)

	ok, _, err := th.Allow(ctx, "k")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(ok))

	// It ends on its own.
	time.Sleep(200 * time.Millisecond)

	ok, _, err = th.Allow(ctx, "k")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(ok))
}

func TestWithoutLockoutOnlyTheWindowBlocks(t *testing.T) {
	th, err := New(newCache(t), contract.ThrottleConfig{
		Enabled: true, MaxAttempts: 2, Window: 50 * time.Millisecond,
	})
	qt.Assert(t, qt.IsNil(err))

	ctx := context.Background()

	for range 3 {
		fail(t, th, "k")
	}

	time.Sleep(80 * time.Millisecond)

	ok, _, err := th.Allow(ctx, "k")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(ok))
}

func TestLockoutReportsRemainingTime(t *testing.T) {
	th, err := New(newCache(t), contract.ThrottleConfig{
		Enabled: true, MaxAttempts: 1, Window: time.Minute, LockoutTTL: time.Minute,
	})
	qt.Assert(t, qt.IsNil(err))

	ctx := context.Background()
	fail(t, th, "k")

	ok, first, err := th.Allow(ctx, "k")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(ok))
	qt.Check(t, qt.IsTrue(first > 0 && first <= time.Minute), qt.Commentf("got %s", first))

	// The wait shrinks as the lockout runs down rather than repeating the full period.
	time.Sleep(60 * time.Millisecond)

	ok, second, err := th.Allow(ctx, "k")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(ok))
	qt.Check(t, qt.IsTrue(second < first), qt.Commentf("first %s, second %s", first, second))
}
