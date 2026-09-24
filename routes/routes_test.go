package routes

import (
	"context"
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"azugo.io/azugo"
	"azugo.io/core"
	"azugo.io/core/config"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

type stubUsers struct{ info auth.UserInfo }

func (s stubUsers) Authenticate(_ context.Context, _, password string) (auth.UserInfo, error) {
	if password == "wrong" {
		return auth.UserInfo{}, auth.ErrInvalidCredentials
	}

	return s.info, nil
}

func (s stubUsers) GetUser(_ context.Context, id string) (auth.UserInfo, error) {
	if id != s.info.ID {
		return auth.UserInfo{}, auth.ErrUserNotFound
	}

	return s.info, nil
}

func newTestAuth(t *testing.T, sessions session.Store, cls ...*client.Client) *auth.Auth {
	return newTestAuthWithOpts(t, sessions, nil, cls...)
}

func newTestAuthWithOpts(t *testing.T, sessions session.Store, opts []auth.Option, cls ...*client.Client) *auth.Auth {
	t.Helper()

	app := core.New()

	conf := config.New()
	qt.Assert(t, qt.IsNil(conf.Load(nil, conf, string(app.Env()))))
	app.SetConfig(nil, conf)
	t.Cleanup(app.Stop)

	cfg := &auth.Configuration{
		Secret:   "0123456789abcdef0123456789abcdef",
		SameSite: "strict",
		Issuer:   "https://issuer.example",
		// validConfig-style literals bypass viper's Bind defaults, so this "default true"
		// field must be set explicitly.
		LogoutInvalidatesCookie: true,
	}

	users := stubUsers{info: auth.UserInfo{ID: "u1", Name: "Alice", Email: "alice@example.com", Scope: "openid profile email"}}

	a, err := auth.New(app, cfg, users, sessions, client.NewMemoryRegistry(cls...), opts...)
	qt.Assert(t, qt.IsNil(err))

	return a
}

func loginFor(t *testing.T, a *auth.Auth, clientID string) auth.LoginResult {
	t.Helper()

	res, err := a.Login(context.Background(), auth.LoginRequest{Credentials: auth.ClientCredentials{ClientID: clientID}, Username: "alice", Password: "right"})
	qt.Assert(t, qt.IsNil(err))

	return res
}

func newTestApp(t *testing.T) *azugo.TestApp {
	t.Helper()

	app := azugo.NewTestApp()
	app.Start(t)
	t.Cleanup(app.Stop)

	return app
}

func TestBindDefaultMountsEverySupportedGroup(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	// No Groups option - SessionGroup is mounted anyway, since it's always supported.
	h := Bind(app, "/auth", a)
	qt.Assert(t, qt.IsNotNil(h))

	tc := app.TestClient()

	resp, err := tc.Get("/auth/session", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	resp2, err := tc.Get("/auth/sessions", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp2.StatusCode(), 200))
}

func TestBindOIDCMountsOIDCOnly(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})

	app := newTestApp(t)
	// OIDC() explicitly opts out of every suppressible group.
	Bind(app, "/auth", a, OIDC())

	tc := app.TestClient()

	resp, err := tc.PostForm("/auth/token", map[string]any{
		"grant_type": "password", "client_id": "spa", "username": "alice", "password": "right",
	})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	resp2, err := tc.Get("/auth/session")
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp2.StatusCode(), 404))
}

func TestBindGroupOptionRestrictsToGiven(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	// A bare Group value is itself an Option.
	Bind(app, "/auth", a, SessionGroup)

	tc := app.TestClient()

	resp, err := tc.Get("/auth/session", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))
}

// nonListingStore wraps an in-memory Store but deliberately does not implement session.Lister.
type nonListingStore struct {
	session.Store
}

func TestNewSkipsListingWhenStoreIsNotLister(t *testing.T) {
	a := newTestAuth(t, nonListingStore{session.NewMemoryStore()}, &client.Client{ID: "spa"})

	h := New(a)
	qt.Check(t, qt.IsNil(h.Session.List))
	qt.Check(t, qt.IsNil(h.Session.Revoke))
}
