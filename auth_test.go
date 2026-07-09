package auth

import (
	"context"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"azugo.io/core"
	"azugo.io/core/config"
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

func newApp(t *testing.T) *core.App {
	t.Helper()

	app := core.New()

	conf := config.New()
	qt.Assert(t, qt.IsNil(conf.Load(nil, conf, string(app.Env()))))
	app.SetConfig(nil, conf)

	t.Cleanup(app.Stop)

	return app
}

func TestNewMaterializesDefaultsAndAccessors(t *testing.T) {
	cfg := validConfig()

	a, err := New(newApp(t), cfg, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
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
	app := newApp(t)

	_, err := New(app, validConfig(), nil, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Check(t, qt.IsNotNil(err))

	_, err = New(app, nil, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Check(t, qt.IsNotNil(err))

	_, err = New(nil, validConfig(), stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Check(t, qt.IsNotNil(err))
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cfg := validConfig()
	cfg.Secret = "tooshort"

	_, err := New(newApp(t), cfg, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
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
	// A supplied JTI store skips the default cache-backed branch.
	a, err := New(newApp(t), validConfig(), stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry(),
		JTIStore(fakeJTI{}))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNotNil(a.JTI()))
}

