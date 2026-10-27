package middleware

import (
	"context"
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"azugo.io/core"
	"azugo.io/core/config"
	"github.com/go-quicktest/qt"
)

type stubUsers struct{ info auth.UserInfo }

func (s stubUsers) Authenticate(context.Context, string, string) (auth.UserInfo, error) {
	return s.info, nil
}

func (s stubUsers) VerifyPassword(context.Context, string, string) error {
	return nil
}

func (s stubUsers) GetUser(_ context.Context, id string) (auth.UserInfo, error) {
	if id != s.info.ID {
		return auth.UserInfo{}, auth.ErrUserNotFound
	}

	return s.info, nil
}

func newTestAuth(t *testing.T, cl *client.Client, opts ...auth.Option) *auth.Auth {
	t.Helper()

	return newTestAuthWithConfig(t, testConfig(), cl, opts...)
}

func testConfig() *auth.Configuration {
	return &auth.Configuration{
		Secret:   "0123456789abcdef0123456789abcdef",
		SameSite: "strict",
		Issuer:   "https://issuer.example",
	}
}

func newTestAuthWithConfig(t *testing.T, cfg *auth.Configuration, cl *client.Client, opts ...auth.Option) *auth.Auth {
	t.Helper()

	app := core.New()

	conf := config.New()
	qt.Assert(t, qt.IsNil(conf.Load(nil, conf, string(app.Env()))))
	app.SetConfig(nil, conf)
	t.Cleanup(app.Stop)

	users := stubUsers{info: auth.UserInfo{ID: "u1", Name: "Alice", Scope: "openid"}}

	a, err := auth.New(app, cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(cl), opts...)
	qt.Assert(t, qt.IsNil(err))

	return a
}

func loginFor(t *testing.T, a *auth.Auth, clientID string) auth.LoginResult {
	t.Helper()

	res, err := a.Login(context.Background(), auth.LoginRequest{Credentials: auth.ClientCredentials{ClientID: clientID}, Username: "alice", Password: "irrelevant"})
	qt.Assert(t, qt.IsNil(err))

	return res
}
