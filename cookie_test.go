package auth

import (
	"testing"

	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
)

func TestCookieSecure(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")

	a, err := New(newApp(t), validConfig(), stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))

	// Unset in development: follow the request scheme.
	qt.Check(t, qt.IsTrue(a.Cookie.Secure(true)))
	qt.Check(t, qt.IsFalse(a.Cookie.Secure(false)))

	// Unset outside development: always Secure.
	t.Setenv("ENVIRONMENT", "production")

	a2, err := New(newApp(t), validConfig(), stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(a2.Cookie.Secure(false)))

	// Explicit value wins over the request scheme.
	insecure := false
	cfg := validConfig()
	cfg.Secure = &insecure

	a3, err := New(newApp(t), cfg, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(a3.Cookie.Secure(true)))
}

func TestCookieSameSite(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")

	cfg := validConfig()
	cfg.SameSite = ""

	a, err := New(newApp(t), cfg, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(a.Cookie.SameSite(), "lax"))

	t.Setenv("ENVIRONMENT", "production")

	cfg2 := validConfig()
	cfg2.SameSite = ""

	a2, err := New(newApp(t), cfg2, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(a2.Cookie.SameSite(), "strict"))

	// Explicit value wins over the environment.
	cfg3 := validConfig()
	cfg3.SameSite = "none"

	a3, err := New(newApp(t), cfg3, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(a3.Cookie.SameSite(), "none"))
}

func TestCookiePathFor(t *testing.T) {
	a, err := New(newApp(t), validConfig(), stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(a.Cookie.Path("", ""), "/"))
	qt.Check(t, qt.Equals(a.Cookie.Path("", "/auth"), "/auth"))
	qt.Check(t, qt.Equals(a.Cookie.Path("/app", "/auth/"), "/app/auth"))
	qt.Check(t, qt.Equals(a.Cookie.Path("/app/", ""), "/app"))

	cfg := validConfig()
	cfg.CookiePath = "/custom"

	a2, err := New(newApp(t), cfg, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(a2.Cookie.Path("/app", "/auth"), "/custom"))
}
