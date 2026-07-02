package auth

import (
	"context"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"azugo.io/core/cache"
	"github.com/go-quicktest/qt"
)

type stubUsers struct{}

func (stubUsers) Authenticate(_ context.Context, _, _ string) (UserInfo, error) {
	return UserInfo{}, nil
}

func (stubUsers) GetUser(_ context.Context, id string) (UserInfo, error) {
	return UserInfo{ID: id}, nil
}

func validConfig() *Configuration {
	return &Configuration{
		Secret:   "0123456789abcdef0123456789abcdef",
		SameSite: "strict",
		Issuer:   "https://issuer.example",
	}
}

func newCache(t *testing.T) *cache.Cache {
	t.Helper()

	c := cache.New(cache.MemoryCache)
	qt.Assert(t, qt.IsNil(c.Start(context.Background())))
	t.Cleanup(c.Close)

	return c
}

func TestNewMaterializesDefaultsAndAccessors(t *testing.T) {
	cfg := validConfig()
	c := newCache(t)

	a, err := New(cfg, c, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))

	// Defaults are materialised through the retained pointer, so a hand-built config validates.
	qt.Check(t, qt.Equals(cfg.AccessTokenTTL, 20*time.Minute))
	qt.Check(t, qt.Equals(cfg.SessionTTL, 8*time.Hour))
	qt.Check(t, qt.Equals(cfg.CookieName, "__session"))

	// Accessors expose the wired dependencies; Config returns the same retained pointer.
	qt.Check(t, qt.IsNotNil(a.Users()))
	qt.Check(t, qt.IsNotNil(a.Sessions()))
	qt.Check(t, qt.IsNotNil(a.Clients()))
	qt.Check(t, qt.IsNotNil(a.JTI())) // default cache-backed store
	qt.Check(t, qt.IsTrue(a.Config() == cfg))
}

func TestNewRequiresDependencies(t *testing.T) {
	c := newCache(t)

	_, err := New(validConfig(), c, nil, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Check(t, qt.IsNotNil(err))

	_, err = New(nil, c, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Check(t, qt.IsNotNil(err))
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cfg := validConfig()
	cfg.Secret = "tooshort"

	_, err := New(cfg, newCache(t), stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Check(t, qt.IsNotNil(err))
}

type fakeJTI struct{}

func (fakeJTI) Issue(context.Context, string, string, time.Duration) error { return nil }
func (fakeJTI) Rotate(context.Context, string, string, string, time.Duration) (bool, error) {
	return true, nil
}
func (fakeJTI) Revoke(context.Context, string) error                   { return nil }
func (fakeJTI) Validate(context.Context, string, string) (bool, error) { return true, nil }

func TestJTIStoreOptionOverridesDefault(t *testing.T) {
	// A supplied JTI store skips the default cache-backed branch, so a nil cache is fine.
	a, err := New(validConfig(), nil, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry(),
		JTIStore(fakeJTI{}))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNotNil(a.JTI()))
}

func TestRunInTx(t *testing.T) {
	ctx := context.Background()

	// Without a Transactor, fn runs directly.
	a, err := New(validConfig(), newCache(t), stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))

	ran := false
	qt.Assert(t, qt.IsNil(a.runInTx(ctx, func(context.Context) error { ran = true; return nil })))
	qt.Check(t, qt.IsTrue(ran))

	// With a Transactor, fn runs inside the unit of work.
	wrapped := false
	tx := TransactorFunc(func(ctx context.Context, fn func(context.Context) error) error {
		wrapped = true
		return fn(ctx)
	})

	a2, err := New(validConfig(), newCache(t), stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry(), Transactor(tx))
	qt.Assert(t, qt.IsNil(err))

	ran2 := false
	qt.Assert(t, qt.IsNil(a2.runInTx(ctx, func(context.Context) error { ran2 = true; return nil })))
	qt.Check(t, qt.IsTrue(wrapped))
	qt.Check(t, qt.IsTrue(ran2))
}
