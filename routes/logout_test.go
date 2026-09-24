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

// newConfirmingAuth builds an Auth that requires logout confirmation.
func newConfirmingAuth(t *testing.T, cl *client.Client) *auth.Auth {
	t.Helper()

	app := core.New()

	conf := config.New()
	qt.Assert(t, qt.IsNil(conf.Load(nil, conf, string(app.Env()))))
	app.SetConfig(nil, conf)
	t.Cleanup(app.Stop)

	cfg := &auth.Configuration{
		Secret:                  "0123456789abcdef0123456789abcdef",
		SameSite:                "lax",
		Issuer:                  "https://issuer.example",
		LogoutInvalidatesCookie: true,
		LogoutPolicy:            auth.LogoutPolicyConfirm,
	}

	users := stubUsers{info: auth.UserInfo{ID: "u1", Name: "Alice", Scope: "openid"}}

	a, err := auth.New(app, cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(cl))
	qt.Assert(t, qt.IsNil(err))

	return a
}

func TestLogoutConfirmationRendersPageAndPostConfirms(t *testing.T) {
	cl := &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeCookie,
	}

	a := newConfirmingAuth(t, cl)
	login := loginFor(t, a, "ssr")

	app := newTestApp(t)
	Bind(app, "/auth", a, LogoutConfirmation(func(ctx *azugo.Context) {
		ctx.Text("confirm?")
	}))

	tc := app.TestClient()
	cookie := tc.WithHeader("Cookie", a.Config().CookieName+"="+login.Cookie.Value)

	// A bare navigation renders the page instead of ending the session.
	resp, err := tc.Get("/auth/logout", cookie)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	body, err := resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(body), "confirm?"))

	_, _, err = a.IntrospectToken(context.Background(), login.Cookie.Value)
	qt.Check(t, qt.IsNil(err))

	// Posting back confirms, which a cross-site navigation cannot do.
	resp2, err := tc.Post("/auth/logout", nil, cookie)
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp2.StatusCode(), 303))

	_, _, err = a.IntrospectToken(context.Background(), login.Cookie.Value)
	qt.Check(t, qt.IsNotNil(err))
}

func TestLogoutConfirmationWithoutPageIsAnError(t *testing.T) {
	cl := &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeCookie,
	}

	a := newConfirmingAuth(t, cl)
	login := loginFor(t, a, "ssr")

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	resp, err := tc.Get("/auth/logout", tc.WithHeader("Cookie", a.Config().CookieName+"="+login.Cookie.Value))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 400))

	_, _, err = a.IntrospectToken(context.Background(), login.Cookie.Value)
	qt.Check(t, qt.IsNil(err))
}
