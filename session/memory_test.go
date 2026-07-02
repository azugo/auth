package session

import (
	"context"
	"testing"
	"time"

	"azugo.io/core/paginator"
	"github.com/go-quicktest/qt"
)

func TestMemoryStoreCreateGet(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	s := &Session{
		ID:        "sid-1",
		UserID:    "user-1",
		Status:    StatusActive,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	qt.Assert(t, qt.IsNil(store.Create(ctx, s)))

	got, err := store.Get(ctx, "sid-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.UserID, "user-1"))
	qt.Check(t, qt.IsTrue(got.Active()))

	_, err = store.Get(ctx, "missing")
	qt.Check(t, qt.ErrorIs(err, ErrNotFound))
}

func TestMemoryStoreCreateAssignsID(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	sess := &Session{UserID: "user-1", ExpiresAt: time.Now().Add(time.Hour)}
	qt.Assert(t, qt.IsNil(store.Create(ctx, sess)))
	qt.Assert(t, qt.IsTrue(sess.ID != ""))
	qt.Check(t, qt.Equals(len(sess.ID), 26)) // ULID string length

	got, err := store.Get(ctx, sess.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.UserID, "user-1"))
}

func TestMemoryStoreGetReturnsCopy(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(store.Create(ctx, &Session{ID: "sid-1", UserID: "user-1", ExpiresAt: time.Now().Add(time.Hour)})))

	got, err := store.Get(ctx, "sid-1")
	qt.Assert(t, qt.IsNil(err))
	got.UserID = "tampered"

	again, err := store.Get(ctx, "sid-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(again.UserID, "user-1"))
}

func TestMemoryStoreTouchAndRevoke(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(store.Create(ctx, &Session{ID: "sid-1", UserID: "user-1", Status: StatusActive, ExpiresAt: time.Now().Add(time.Hour)})))

	qt.Assert(t, qt.IsNil(store.Touch(ctx, "sid-1")))
	got, err := store.Get(ctx, "sid-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(got.LastSeen.IsZero()))

	qt.Assert(t, qt.IsNil(store.Revoke(ctx, "sid-1")))
	got, err = store.Get(ctx, "sid-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNotNil(got.RevokedAt))
	qt.Check(t, qt.IsFalse(got.Active()))

	// A revoked session is retained (still Get-able for Lister) but no longer touchable.
	qt.Check(t, qt.ErrorIs(store.Touch(ctx, "sid-1"), ErrNotFound))

	qt.Check(t, qt.ErrorIs(store.Touch(ctx, "missing"), ErrNotFound))
}

func TestMemoryStoreCreateRejectsDead(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	// Expired and unset (zero) ExpiresAt are rejected.
	qt.Check(t, qt.IsNotNil(store.Create(ctx, &Session{ID: "past", ExpiresAt: time.Now().Add(-time.Minute)})))
	qt.Check(t, qt.IsNotNil(store.Create(ctx, &Session{ID: "unset"})))

	// A pre-revoked session is rejected too.
	now := time.Now()
	qt.Check(t, qt.IsNotNil(store.Create(ctx, &Session{ID: "revoked", ExpiresAt: now.Add(time.Hour), RevokedAt: &now})))
}

func TestMemoryStoreTouchRejectsExpired(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	// Create a barely-future session (Create rejects an already-expired one), then let it lapse.
	qt.Assert(t, qt.IsNil(store.Create(ctx, &Session{ID: "sid-1", UserID: "user-1", Status: StatusActive, ExpiresAt: time.Now().Add(20 * time.Millisecond)})))
	time.Sleep(30 * time.Millisecond)

	qt.Check(t, qt.ErrorIs(store.Touch(ctx, "sid-1"), ErrNotFound))
}

func TestMemoryStoreListOrdersByLastSeenDesc(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	now := time.Now()
	qt.Assert(t, qt.IsNil(store.Create(ctx, &Session{ID: "old", UserID: "user-1", LastSeen: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)})))
	qt.Assert(t, qt.IsNil(store.Create(ctx, &Session{ID: "new", UserID: "user-1", LastSeen: now, ExpiresAt: now.Add(time.Hour)})))
	qt.Assert(t, qt.IsNil(store.Create(ctx, &Session{ID: "other", UserID: "user-2", LastSeen: now, ExpiresAt: now.Add(time.Hour)})))

	// The in-memory store implements the optional Lister capability.
	lister, ok := store.(Lister)
	qt.Assert(t, qt.IsTrue(ok))

	// reqPage builds a request paginator the way ctx.Paging() does — with a placeholder total of
	// page*size so the requested page is not clamped away.
	reqPage := func(page, size int) *paginator.Paginator { return paginator.New(page*size, size, page) }

	list, pages, err := lister.List(ctx, "user-1", nil, reqPage(1, 20))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(pages.Total(), 2))
	qt.Assert(t, qt.Equals(len(list), 2))
	qt.Check(t, qt.Equals(list[0].ID, "new"))
	qt.Check(t, qt.Equals(list[1].ID, "old"))

	// Second page of size 1 returns the older session; total still reflects all matches.
	list, pages, err = lister.List(ctx, "user-1", nil, reqPage(2, 1))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(pages.Total(), 2))
	qt.Assert(t, qt.Equals(len(list), 1))
	qt.Check(t, qt.Equals(list[0].ID, "old"))

	empty, pages, err := lister.List(ctx, "nobody", nil, reqPage(1, 20))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(pages.Total(), 0))
	qt.Check(t, qt.Equals(len(empty), 0))
}

func TestMemoryStoreListNilPageReturnsAll(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	lister := store.(Lister)

	now := time.Now()
	for _, id := range []string{"a", "b", "c"} {
		qt.Assert(t, qt.IsNil(store.Create(ctx, &Session{ID: id, UserID: "user-1", Status: StatusActive, ExpiresAt: now.Add(time.Hour)})))
	}

	// A nil paginator returns every match on a single page.
	all, pages, err := lister.List(ctx, "user-1", nil, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(all), 3))
	qt.Check(t, qt.Equals(pages.Total(), 3))
}

func TestMemoryStoreListActiveOnly(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	lister := store.(Lister)

	now := time.Now()
	qt.Assert(t, qt.IsNil(store.Create(ctx, &Session{ID: "active", UserID: "user-1", Status: StatusActive, ExpiresAt: now.Add(time.Hour)})))
	qt.Assert(t, qt.IsNil(store.Create(ctx, &Session{ID: "pending", UserID: "user-1", Status: StatusPendingMFA, ExpiresAt: now.Add(time.Hour)})))
	qt.Assert(t, qt.IsNil(store.Create(ctx, &Session{ID: "revoked", UserID: "user-1", Status: StatusActive, ExpiresAt: now.Add(time.Hour)})))
	qt.Assert(t, qt.IsNil(store.Revoke(ctx, "revoked")))

	// Unfiltered: all three.
	all, _, err := lister.List(ctx, "user-1", nil, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(all), 3))

	// ActiveOnly: excludes the pending and revoked ones.
	active, pages, err := lister.List(ctx, "user-1", &Filter{ActiveOnly: true}, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(active), 1))
	qt.Check(t, qt.Equals(active[0].ID, "active"))
	qt.Check(t, qt.Equals(pages.Total(), 1))
}

func TestPendingStatus(t *testing.T) {
	s := &Session{Status: StatusPendingMFA, ExpiresAt: time.Now().Add(time.Hour)}
	qt.Check(t, qt.IsTrue(s.Pending()))
	qt.Check(t, qt.IsFalse(s.Active()))
}
