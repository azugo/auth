package jti

import (
	"context"
	"testing"
	"time"

	"azugo.io/core/cache"
	"github.com/go-quicktest/qt"
)

func newStore(t *testing.T) Store {
	t.Helper()

	c := cache.New(cache.MemoryCache)
	qt.Assert(t, qt.IsNil(c.Start(context.Background())))
	t.Cleanup(c.Close)

	store, err := NewCacheStore(c)
	qt.Assert(t, qt.IsNil(err))

	return store
}

func TestIssueAndValidate(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(store.Issue(ctx, "jti-1", "sid-1", time.Minute)))

	ok, err := store.Validate(ctx, "jti-1", "sid-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(ok))

	// Wrong session and unknown jti both fail closed.
	ok, err = store.Validate(ctx, "jti-1", "other")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(ok))

	ok, err = store.Validate(ctx, "missing", "sid-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(ok))
}

func TestRotate(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(store.Issue(ctx, "jti-1", "sid-1", time.Minute)))

	ok, err := store.Rotate(ctx, "jti-1", "jti-2", "sid-1", time.Minute)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(ok))

	valid, err := store.Validate(ctx, "jti-2", "sid-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(valid))

	// The old jti is gone.
	valid, err = store.Validate(ctx, "jti-1", "sid-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(valid))

	// Rotating an absent jti is treated as a replay (false, no error).
	ok, err = store.Rotate(ctx, "jti-1", "jti-3", "sid-1", time.Minute)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(ok))
}

func TestRotateSessionMismatch(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(store.Issue(ctx, "jti-1", "sid-1", time.Minute)))

	ok, err := store.Rotate(ctx, "jti-1", "jti-2", "other-sid", time.Minute)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(ok))
}

func TestRevoke(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(store.Issue(ctx, "jti-1", "sid-1", time.Minute)))

	qt.Assert(t, qt.IsNil(store.Revoke(ctx, "jti-1")))

	ok, err := store.Validate(ctx, "jti-1", "sid-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(ok))
}
