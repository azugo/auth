package jti

import (
	"context"
	"sync"
	"testing"
	"time"

	"azugo.io/core/cache"
	"github.com/go-quicktest/qt"
)

func newDenyList(t *testing.T) DenyList {
	t.Helper()

	c := cache.New(cache.MemoryCache)
	qt.Assert(t, qt.IsNil(c.Start(context.Background())))
	t.Cleanup(c.Close)

	list, err := NewCacheDenyList(c, "test:denied")
	qt.Assert(t, qt.IsNil(err))

	return list
}

func TestDenyAndDenied(t *testing.T) {
	list := newDenyList(t)
	ctx := context.Background()

	denied, err := list.Denied(ctx, "jti-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(denied))

	qt.Assert(t, qt.IsNil(list.Deny(ctx, "jti-1", time.Minute)))

	denied, err = list.Denied(ctx, "jti-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(denied))

	// A non-positive TTL is a no-op: an already-expired entry is pointless.
	qt.Assert(t, qt.IsNil(list.Deny(ctx, "jti-2", 0)))

	denied, err = list.Denied(ctx, "jti-2")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(denied))
}

func TestClaimIsSingleWinner(t *testing.T) {
	list := newDenyList(t)
	ctx := context.Background()

	claimed, err := list.Claim(ctx, "jti-1", time.Minute)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(claimed))

	claimed, err = list.Claim(ctx, "jti-1", time.Minute)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(claimed))
}

func TestConcurrentClaimYieldsOneWinner(t *testing.T) {
	list := newDenyList(t)
	ctx := context.Background()

	const racers = 16

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)

	wg.Add(racers)

	for range racers {
		go func() {
			defer wg.Done()

			claimed, err := list.Claim(ctx, "jti-race", time.Minute)
			qt.Check(t, qt.IsNil(err))

			if claimed {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	qt.Check(t, qt.Equals(wins, 1))
}
