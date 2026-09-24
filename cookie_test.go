package auth

import (
	"testing"

	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
)

func TestCookieSameSite(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")

	cfg := validConfig()
	cfg.SameSite = ""

	a, err := New(newApp(t), cfg, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(a.Cookie.SameSite(), azugo.CookieSameSiteLax))

	t.Setenv("ENVIRONMENT", "production")

	cfg2 := validConfig()
	cfg2.SameSite = ""

	a2, err := New(newApp(t), cfg2, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(a2.Cookie.SameSite(), azugo.CookieSameSiteStrict))

	// Explicit value wins over the environment.
	cfg3 := validConfig()
	cfg3.SameSite = "none"

	a3, err := New(newApp(t), cfg3, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(a3.Cookie.SameSite(), azugo.CookieSameSiteNone))
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

func TestCookieScopeToBasePath(t *testing.T) {
	a, err := New(newApp(t), validConfig(), stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry(),
		CookieScopeToBasePath())
	qt.Assert(t, qt.IsNil(err))

	// mountPath is ignored - the cookie is scoped to the app's base path, not the auth mount.
	qt.Check(t, qt.Equals(a.Cookie.Path("", "/auth"), "/"))
	qt.Check(t, qt.Equals(a.Cookie.Path("/app", "/auth"), "/app"))

	// An explicit CookiePath still takes precedence.
	cfg := validConfig()
	cfg.CookiePath = "/custom"

	a2, err := New(newApp(t), cfg, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry(),
		CookieScopeToBasePath())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(a2.Cookie.Path("/app", "/auth"), "/custom"))
}
