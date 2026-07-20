package middleware

import (
	"testing"

	"azugo.io/auth/client"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func newTestApp(t *testing.T) *azugo.TestApp {
	t.Helper()

	app := azugo.NewTestApp()
	app.Start(t)
	t.Cleanup(app.Stop)

	return app
}

func TestAuthMiddlewareBearer(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	app.Use(Auth(a))
	app.Get("/", func(ctx *azugo.Context) {
		if ctx.User().Authorized() {
			ctx.Text(ctx.User().ID())

			return
		}

		ctx.Text("anonymous")
	})

	tc := app.TestClient()

	resp, err := tc.Get("/", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(body), "u1"))
}

func TestAuthMiddlewareNeverHaltsOnMissingCredential(t *testing.T) {
	a := newTestAuth(t, &client.Client{ID: "spa"})

	app := newTestApp(t)
	app.Use(Auth(a))
	app.Get("/", func(ctx *azugo.Context) {
		if ctx.User().Authorized() {
			ctx.Text("authorized")

			return
		}

		ctx.Text("anonymous")
	})

	resp, err := app.TestClient().Get("/")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(body), "anonymous"))
}

func TestAuthMiddlewareCookieOptIn(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeCookie,
	})
	login := loginFor(t, a, "ssr")

	app := newTestApp(t)
	app.Use(Auth(a, Cookie()))
	app.Get("/", func(ctx *azugo.Context) {
		if ctx.User().Authorized() {
			ctx.Text(ctx.User().ID())

			return
		}

		ctx.Text("anonymous")
	})

	tc := app.TestClient()

	resp, err := tc.Get("/", tc.WithCookie(a.Config().CookieName, login.Cookie.Value))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(body), "u1"))
}

func TestAuthMiddlewareIgnoresCookieWithoutOption(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeCookie,
	})
	login := loginFor(t, a, "ssr")

	app := newTestApp(t)
	app.Use(Auth(a)) // no Cookie() option
	app.Get("/", func(ctx *azugo.Context) {
		if ctx.User().Authorized() {
			ctx.Text(ctx.User().ID())

			return
		}

		ctx.Text("anonymous")
	})

	tc := app.TestClient()

	resp, err := tc.Get("/", tc.WithCookie(a.Config().CookieName, login.Cookie.Value))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(body), "anonymous"))
}
