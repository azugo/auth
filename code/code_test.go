package code

import (
	"context"
	"errors"
	"testing"
	"time"

	"azugo.io/core/cache"
	"github.com/go-quicktest/qt"
)

// settle waits for the eventually-consistent memory cache to apply a write.
func settle() { time.Sleep(10 * time.Millisecond) }

func newStore(t *testing.T) Store {
	t.Helper()

	c := cache.New(cache.MemoryCache)
	qt.Assert(t, qt.IsNil(c.Start(context.Background())))
	t.Cleanup(c.Close)

	store, err := NewCacheStore(c, time.Minute)
	qt.Assert(t, qt.IsNil(err))

	return store
}

func testCode(val string) *AuthorizationCode {
	return &AuthorizationCode{
		Code: val, ClientID: "web", UserID: "u1", SessionID: "s1",
		RedirectURI: "https://web.example/callback", Scope: "openid",
		CodeChallenge: "challenge", CodeChallengeMethod: "S256",
		ExpiresAt: time.Now().Add(time.Minute),
	}
}

func TestConsumeIsSingleUse(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(store.Save(ctx, testCode("c1"))))
	settle()

	rec, err := store.Consume(ctx, "c1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(rec.ClientID, "web"))
	qt.Check(t, qt.Equals(rec.SessionID, "s1"))
	settle()

	// The second consume reports the replay together with the bound record.
	rec2, err := store.Consume(ctx, "c1")
	qt.Assert(t, qt.IsTrue(errors.Is(err, ErrReplayed)))
	qt.Assert(t, qt.IsNotNil(rec2))
	qt.Check(t, qt.Equals(rec2.SessionID, "s1"))
}

func TestConsumeUnknownCode(t *testing.T) {
	store := newStore(t)

	_, err := store.Consume(context.Background(), "missing")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))
}

func TestConsumeExpiredCode(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	rec := testCode("c2")
	rec.ExpiresAt = time.Now().Add(50 * time.Millisecond)
	qt.Assert(t, qt.IsNil(store.Save(ctx, rec)))

	time.Sleep(80 * time.Millisecond)

	_, err := store.Consume(ctx, "c2")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))
}
