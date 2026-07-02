package session

import (
	"context"
	"testing"
	"time"

	"azugo.io/core/cache"
	"github.com/go-quicktest/qt"
)

// settle waits for the eventually-consistent memory cache to apply a write.
func settle() { time.Sleep(10 * time.Millisecond) }

func newCacheStore(t *testing.T) Store {
	t.Helper()

	c := cache.New(cache.MemoryCache)
	qt.Assert(t, qt.IsNil(c.Start(context.Background())))
	t.Cleanup(c.Close)

	store, err := NewCacheStore(c)
	qt.Assert(t, qt.IsNil(err))

	return store
}

func TestCacheStoreCreateGet(t *testing.T) {
	store := newCacheStore(t)
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(store.Create(ctx, &Session{
		ID:        "sid-1",
		UserID:    "user-1",
		Status:    StatusActive,
		ExpiresAt: time.Now().Add(time.Hour),
	})))
	settle()

	got, err := store.Get(ctx, "sid-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.UserID, "user-1"))
	qt.Check(t, qt.IsTrue(got.Active()))

	_, err = store.Get(ctx, "missing")
	qt.Check(t, qt.ErrorIs(err, ErrNotFound))
}

func TestCacheStoreCreateAssignsID(t *testing.T) {
	store := newCacheStore(t)
	ctx := context.Background()

	sess := &Session{UserID: "user-1", Status: StatusActive, ExpiresAt: time.Now().Add(time.Hour)}
	qt.Assert(t, qt.IsNil(store.Create(ctx, sess)))
	qt.Assert(t, qt.IsTrue(sess.ID != ""))
	qt.Check(t, qt.Equals(len(sess.ID), 26)) // ULID string length
	settle()

	got, err := store.Get(ctx, sess.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.UserID, "user-1"))
}

func TestCacheStoreCreateRejectsDead(t *testing.T) {
	store := newCacheStore(t)
	ctx := context.Background()

	// Past expiry and unset (zero) ExpiresAt are both rejected rather than stored.
	qt.Check(t, qt.IsNotNil(store.Create(ctx, &Session{ID: "past", ExpiresAt: time.Now().Add(-time.Minute)})))
	qt.Check(t, qt.IsNotNil(store.Create(ctx, &Session{ID: "unset"})))

	// A pre-revoked session is rejected too.
	now := time.Now()
	qt.Check(t, qt.IsNotNil(store.Create(ctx, &Session{ID: "revoked", ExpiresAt: now.Add(time.Hour), RevokedAt: &now})))
}

func TestCacheStoreTouch(t *testing.T) {
	store := newCacheStore(t)
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(store.Create(ctx, &Session{ID: "sid-1", UserID: "user-1", Status: StatusActive, ExpiresAt: time.Now().Add(time.Hour)})))
	settle()

	qt.Assert(t, qt.IsNil(store.Touch(ctx, "sid-1")))
	settle()

	got, err := store.Get(ctx, "sid-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(got.LastSeen.IsZero()))

	qt.Check(t, qt.ErrorIs(store.Touch(ctx, "missing"), ErrNotFound))
}

func TestCacheStoreRevoke(t *testing.T) {
	store := newCacheStore(t)
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(store.Create(ctx, &Session{ID: "sid-1", UserID: "user-1", Status: StatusActive, ExpiresAt: time.Now().Add(time.Hour)})))
	settle()

	qt.Assert(t, qt.IsNil(store.Revoke(ctx, "sid-1")))
	settle()

	// A revoked session is deleted, so it reads as not found.
	_, err := store.Get(ctx, "sid-1")
	qt.Check(t, qt.ErrorIs(err, ErrNotFound))

	// Revoking an absent session is an idempotent no-op.
	qt.Check(t, qt.IsNil(store.Revoke(ctx, "missing")))
}

// TestCacheStoreOmitsLister documents that the cache-backed store intentionally does NOT provide
// the optional Lister capability, so the session-list endpoints stay unmounted for it.
func TestCacheStoreOmitsLister(t *testing.T) {
	_, ok := newCacheStore(t).(Lister)
	qt.Check(t, qt.IsFalse(ok))
}
