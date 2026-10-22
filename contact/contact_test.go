package contact

import (
	"context"
	"errors"
	"testing"
	"time"

	"azugo.io/auth/reset"

	"azugo.io/core/cache"
	"github.com/go-quicktest/qt"
)

func newStore(t *testing.T) Store {
	t.Helper()

	c := cache.New(cache.MemoryCache)
	qt.Assert(t, qt.IsNil(c.Start(context.Background())))
	t.Cleanup(c.Close)

	s, err := NewCacheStore(c)
	qt.Assert(t, qt.IsNil(err))

	return s
}

func request(id string, ttl time.Duration) *reset.Request {
	return &reset.Request{ID: id, UserID: "u1", Identifier: "a@example.com", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(ttl)}
}

func TestCacheStoreKeepsOneOpenRequestPerChannel(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	_, err := s.Open(ctx, "email", "u1", "a@example.com")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))

	qt.Assert(t, qt.IsNil(s.Save(ctx, "email", request("r1", time.Minute))))
	qt.Assert(t, qt.IsNil(s.Save(ctx, "phone", request("p1", time.Minute))))

	open, err := s.Open(ctx, "email", "u1", "a@example.com")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(open.ID, "r1"))

	// A new request replaces the one open on the same channel only.
	qt.Assert(t, qt.IsNil(s.Save(ctx, "email", request("r2", time.Minute))))

	_, err = s.Get(ctx, "r1")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))

	open, err = s.Open(ctx, "email", "u1", "a@example.com")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(open.ID, "r2"))

	phone, err := s.Open(ctx, "phone", "u1", "a@example.com")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(phone.ID, "p1"))
}

func TestCacheStoreConsumeIsSingleUse(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(s.Save(ctx, "email", request("r1", time.Minute))))

	got, err := s.Consume(ctx, "r1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.ID, "r1"))

	_, err = s.Consume(ctx, "r1")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))

	_, err = s.Open(ctx, "email", "u1", "a@example.com")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))
}

func TestCacheStoreSkipsExpired(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(s.Save(ctx, "email", request("r1", -time.Second))))

	_, err := s.Get(ctx, "r1")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))
}

func TestCacheStoreKeepsOneOpenRequestPerAddress(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	other := request("r2", time.Minute)
	other.Identifier = "b@example.com"

	qt.Assert(t, qt.IsNil(s.Save(ctx, "email", request("r1", time.Minute))))
	qt.Assert(t, qt.IsNil(s.Save(ctx, "email", other)))

	// Both addresses of the user are pending at once.
	first, err := s.Open(ctx, "email", "u1", "a@example.com")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(first.ID, "r1"))

	second, err := s.Open(ctx, "email", "u1", "b@example.com")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(second.ID, "r2"))

	// A new request replaces only the one for the same address, and consuming clears only its own index.
	qt.Assert(t, qt.IsNil(s.Save(ctx, "email", request("r3", time.Minute))))

	_, err = s.Get(ctx, "r1")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))

	_, err = s.Consume(ctx, "r3")
	qt.Assert(t, qt.IsNil(err))

	_, err = s.Open(ctx, "email", "u1", "a@example.com")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))

	still, err := s.Open(ctx, "email", "u1", "b@example.com")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(still.ID, "r2"))
}
