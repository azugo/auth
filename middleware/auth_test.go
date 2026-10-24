package middleware

import (
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/apikey"
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

func TestAuthMiddlewareAudience(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	login := loginFor(t, a, "spa")

	for audience, want := range map[string]string{"spa": "u1", "other": "anonymous"} {
		app := newTestApp(t)
		app.Use(Auth(a, Audience(audience)))
		app.Get("/", func(ctx *azugo.Context) {
			if ctx.User().Authorized() {
				ctx.Text(ctx.User().ID())

				return
			}

			ctx.Text("anonymous")
		})

		tc := app.TestClient()

		resp, err := tc.Get("/", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
		qt.Assert(t, qt.IsNil(err))

		body, err := resp.BodyUncompressed()
		fasthttp.ReleaseResponse(resp)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(string(body), want), qt.Commentf("audience %q", audience))
	}
}

func TestAuthMiddlewareAPIKey(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	}, auth.APIKeyStore(apikey.NewMemoryStore()))
	login := loginFor(t, a, "spa")

	res, err := a.CreateAPIKey(t.Context(), auth.CreateAPIKeyRequest{Token: login.AccessToken, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))

	handler := func(ctx *azugo.Context) {
		if ctx.User().Authorized() {
			ctx.Text(ctx.User().ID())

			return
		}

		ctx.Text("anonymous")
	}

	app := newTestApp(t)
	app.Get("/keys", Auth(a, APIKey())(handler))
	app.Get("/plain", Auth(a)(handler))

	tc := app.TestClient()

	for path, want := range map[string]string{"/keys": "u1", "/plain": "anonymous"} {
		resp, err := tc.Get(path, tc.WithHeader("Authorization", "Bearer "+res.Token))
		qt.Assert(t, qt.IsNil(err))

		body, err := resp.BodyUncompressed()
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(string(body), want), qt.Commentf(path))
		fasthttp.ReleaseResponse(resp)
	}

	// Session tokens keep working with the option.
	resp, err := tc.Get("/keys", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(body), "u1"))
}

func TestAuthMiddlewareRefusesAPIKeyCookie(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	}, auth.APIKeyStore(apikey.NewMemoryStore()))
	login := loginFor(t, a, "spa")

	res, err := a.CreateAPIKey(t.Context(), auth.CreateAPIKeyRequest{Token: login.AccessToken, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))

	app := newTestApp(t)
	app.Use(Auth(a, Cookie(), APIKey()))
	app.Get("/", func(ctx *azugo.Context) {
		if ctx.User().Authorized() {
			ctx.Text(ctx.User().ID())

			return
		}

		ctx.Text("anonymous")
	})

	tc := app.TestClient()

	for name, opt := range map[string]azugo.TestClientOption{
		"cookie":  tc.WithCookie(a.Config().CookieName, res.Token),
		"bearer":  tc.WithHeader("Authorization", "Bearer "+res.Token),
		"session": tc.WithCookie(a.Config().CookieName, login.Cookie.Value),
	} {
		resp, err := tc.Get("/", opt)
		qt.Assert(t, qt.IsNil(err))

		body, err := resp.BodyUncompressed()
		qt.Assert(t, qt.IsNil(err))

		want := "u1"
		if name == "cookie" {
			want = "anonymous"
		}

		qt.Check(t, qt.Equals(string(body), want), qt.Commentf(name))
		fasthttp.ReleaseResponse(resp)
	}
}
