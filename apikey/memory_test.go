package apikey

import (
	"azugo.io/auth/contract"
	"context"
	"testing"
	"time"
	"unsafe"

	"azugo.io/core/paginator"
	"github.com/go-quicktest/qt"
)

func TestMemoryStoreListOrdersAndFilters(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	now := time.Now()

	qt.Assert(t, qt.IsNil(s.Create(ctx, &Key{ID: "a", UserID: "u1", CreatedAt: now.Add(-2 * time.Hour)})))
	qt.Assert(t, qt.IsNil(s.Create(ctx, &Key{ID: "b", UserID: "u1", CreatedAt: now.Add(-time.Hour)})))
	qt.Assert(t, qt.IsNil(s.Create(ctx, &Key{ID: "c", UserID: "u2", CreatedAt: now})))
	qt.Assert(t, qt.IsNil(s.Revoke(ctx, "a")))

	keys, pages, err := s.List(ctx, "u1", nil, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(keys, 2))
	qt.Check(t, qt.Equals(keys[0].ID, "b"))
	qt.Check(t, qt.Equals(pages.Total(), 2))

	active, _, err := s.List(ctx, "u1", &Filter{ActiveOnly: true}, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(active, 1))
	qt.Check(t, qt.Equals(active[0].ID, "b"))

	paged, _, err := s.List(ctx, "u1", nil, paginator.New(2, 1, 2))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(paged, 1))
	qt.Check(t, qt.Equals(paged[0].ID, "a"))
}

func TestMemoryStoreGetIncludesRevoked(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(s.Create(ctx, &Key{ID: "a", UserID: "u1"})))
	qt.Check(t, qt.IsNotNil(s.Create(ctx, &Key{ID: "a", UserID: "u1"})))
	qt.Assert(t, qt.IsNil(s.Revoke(ctx, "a")))

	k, err := s.Get(ctx, "a")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(k.Valid()))

	_, err = s.Get(ctx, "missing")
	qt.Check(t, qt.ErrorIs(err, ErrNotFound))
	qt.Check(t, qt.ErrorIs(s.Revoke(ctx, "missing"), ErrNotFound))
	qt.Check(t, qt.ErrorIs(s.Revoke(ctx, "a"), ErrNotFound))
}

func TestKeyMatches(t *testing.T) {
	k := &Key{Hash: HashSecret("right")}

	qt.Check(t, qt.IsTrue(k.Matches("right")))
	qt.Check(t, qt.IsFalse(k.Matches("wrong")))
	qt.Check(t, qt.IsFalse((&Key{}).Matches("")))
}

func TestMemoryStoreRotate(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	at := time.Now()

	qt.Assert(t, qt.IsNil(s.Create(ctx, &Key{ID: "a", UserID: "u1", Hash: HashSecret("old")})))
	qt.Assert(t, qt.IsNil(s.Rotate(ctx, "a", HashSecret("new"), at)))

	k, err := s.Get(ctx, "a")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(k.Matches("new")))
	qt.Check(t, qt.IsFalse(k.Matches("old")))
	qt.Assert(t, qt.IsNotNil(k.RotatedAt))
	qt.Check(t, qt.IsTrue(k.RotatedAt.Equal(at)))

	qt.Check(t, qt.ErrorIs(s.Rotate(ctx, "missing", HashSecret("x"), at), ErrNotFound))

	// A revoked key keeps its hash and revocation.
	qt.Assert(t, qt.IsNil(s.Revoke(ctx, "a")))
	qt.Check(t, qt.ErrorIs(s.Rotate(ctx, "a", HashSecret("later"), at.Add(time.Second)), ErrNotFound))

	k, err = s.Get(ctx, "a")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(k.Matches("new")))
	qt.Check(t, qt.IsNotNil(k.RevokedAt))
}

func TestMemoryStoreListOrdersEqualTimesByID(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	at := time.Now()

	for _, id := range []string{"c", "a", "d", "b"} {
		qt.Assert(t, qt.IsNil(s.Create(ctx, &Key{ID: id, UserID: "u1", CreatedAt: at})))
	}

	var ids []string

	for page := 1; page <= 2; page++ {
		keys, _, err := s.List(ctx, "u1", nil, paginator.New(4, 2, page))
		qt.Assert(t, qt.IsNil(err))

		for _, k := range keys {
			ids = append(ids, k.ID)
		}
	}

	qt.Check(t, qt.DeepEquals(ids, []string{"a", "b", "c", "d"}))
}

func TestMemoryStoreOwnsItsStrings(t *testing.T) {
	s := NewMemoryStore()
	buf := []byte("deploy-key")
	alias := unsafe.String(&buf[0], len(buf))

	qt.Assert(t, qt.IsNil(s.Create(context.Background(), &Key{ID: alias, UserID: "u1", Name: alias, Scope: alias})))

	copy(buf, "XXXXXXXXXX")

	k, err := s.Get(context.Background(), "deploy-key")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(k.ID, "deploy-key"))
	qt.Check(t, qt.Equals(k.Name, "deploy-key"))
	qt.Check(t, qt.Equals(k.Scope, "deploy-key"))
}

func TestMemoryStoreOwnsItsTimes(t *testing.T) {
	s := NewMemoryStore()
	expires := time.Now().Add(time.Hour)

	qt.Assert(t, qt.IsNil(s.Create(context.Background(), &Key{ID: "a", UserID: "u1", ExpiresAt: &expires})))

	// Moving the caller's time leaves the stored expiry alone.
	expires = time.Now().Add(-time.Hour)

	k, err := s.Get(context.Background(), "a")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(k.Valid()))

	// Neither does changing a returned copy.
	*k.ExpiresAt = expires

	k, err = s.Get(context.Background(), "a")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(k.Valid()))
}

func TestMemoryStoreRevokeAll(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)

	qt.Assert(t, qt.IsNil(s.Create(ctx, &Key{ID: "a", UserID: "u1"})))
	qt.Assert(t, qt.IsNil(s.Create(ctx, &Key{ID: "b", UserID: "u1"})))
	qt.Assert(t, qt.IsNil(s.Create(ctx, &Key{ID: "old", UserID: "u1", ExpiresAt: &past})))
	qt.Assert(t, qt.IsNil(s.Create(ctx, &Key{ID: "c", UserID: "u2"})))

	// Only the user's valid keys are revoked and reported.
	revoked, err := s.RevokeAll(ctx, "u1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.ContentEquals(revoked, []string{"a", "b"}))

	active, _, err := s.List(ctx, "u1", &Filter{ActiveOnly: true}, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(active, 0))

	other, err := s.Get(ctx, "c")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(other.Valid()))

	again, err := s.RevokeAll(ctx, "u1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(again, 0))
}

func TestMemoryStoreSubjectKeys(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	deployment := &contract.AuthorizationDetail{Type: "deployment", Identifier: "1", Actions: []string{"deploy"}}

	qt.Assert(t, qt.IsNil(s.Create(ctx, &Key{ID: "own", UserID: "u1"})))
	qt.Assert(t, qt.IsNil(s.Create(ctx, &Key{ID: "d1", Subject: deployment})))

	// One unrevoked key per object.
	err := s.Create(ctx, &Key{ID: "d1-again", Subject: deployment})
	qt.Check(t, qt.ErrorIs(err, ErrInvalidKey))

	found, err := s.GetBySubject(ctx, "deployment", "1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(found.ID, "d1"))
	qt.Check(t, qt.DeepEquals(found.Subject, deployment))

	_, err = s.GetBySubject(ctx, "deployment", "2")
	qt.Check(t, qt.ErrorIs(err, ErrNotFound))

	// Subject keys are no user's, so a user's list and RevokeAll leave them.
	own, _, err := s.List(ctx, "", nil, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(own, 1))

	qt.Assert(t, qt.IsNil(s.Revoke(ctx, "d1")))

	_, err = s.GetBySubject(ctx, "deployment", "1")
	qt.Check(t, qt.ErrorIs(err, ErrNotFound))

	qt.Assert(t, qt.IsNil(s.Create(ctx, &Key{ID: "d1-new", Subject: deployment})))
}
