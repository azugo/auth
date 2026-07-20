package middleware

import (
	"testing"

	"azugo.io/auth/client"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestRequireAuthRejectsAnonymous(t *testing.T) {
	a := newTestAuth(t, &client.Client{ID: "spa"})

	app := newTestApp(t)
	app.Use(Auth(a))
	app.Use(RequireAuth())
	app.Get("/", func(ctx *azugo.Context) {
		ctx.Text("secret")
	})

	resp, err := app.TestClient().Get("/")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), http.StatusUnauthorized))
	qt.Check(t, qt.IsTrue(len(resp.Header.Peek(http.HeaderWWWAuthenticate)) > 0))
}

func TestRequireAuthPassesAuthorized(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	app.Use(Auth(a))
	app.Use(RequireAuth())
	app.Get("/", func(ctx *azugo.Context) {
		ctx.Text("secret")
	})

	tc := app.TestClient()

	resp, err := tc.Get("/", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), http.StatusOK))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(body), "secret"))
}

func TestRequireAuthRedirectToRedirectsAnonymous(t *testing.T) {
	a := newTestAuth(t, &client.Client{ID: "spa"})

	app := newTestApp(t)
	app.Use(Auth(a))
	app.Use(RequireAuth(RedirectTo("/login")))
	app.Get("/", func(ctx *azugo.Context) {
		ctx.Text("secret")
	})

	resp, err := app.TestClient().Get("/")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), http.StatusFound))
	qt.Check(t, qt.Equals(string(resp.Header.Peek(http.HeaderLocation)), "/login"))
}

func TestRequireAuthRedirectToWithReturnToAppendsRequestedPath(t *testing.T) {
	a := newTestAuth(t, &client.Client{ID: "spa"})

	app := newTestApp(t)
	app.Use(Auth(a))
	app.Use(RequireAuth(RedirectTo("/login"), ReturnTo()))
	app.Get("/sessions", func(ctx *azugo.Context) {
		ctx.Text("secret")
	})

	resp, err := app.TestClient().Get("/sessions")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), http.StatusFound))
	qt.Check(t, qt.Equals(string(resp.Header.Peek(http.HeaderLocation)), "/login?return_to=%2Fsessions"))
}

func TestRequireAuthRedirectToWithReturnToPreservesQueryString(t *testing.T) {
	a := newTestAuth(t, &client.Client{ID: "spa"})

	app := newTestApp(t)
	app.Use(Auth(a))
	app.Use(RequireAuth(RedirectTo("/login"), ReturnTo()))
	app.Get("/sessions", func(ctx *azugo.Context) {
		ctx.Text("secret")
	})

	resp, err := app.TestClient().Get("/sessions?tab=security")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), http.StatusFound))
	qt.Check(t, qt.Equals(string(resp.Header.Peek(http.HeaderLocation)), "/login?return_to=%2Fsessions%3Ftab%3Dsecurity"))
}

func TestRequireAuthRedirectToPassesAuthorized(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	app.Use(Auth(a))
	app.Use(RequireAuth(RedirectTo("/login")))
	app.Get("/", func(ctx *azugo.Context) {
		ctx.Text("secret")
	})

	tc := app.TestClient()

	resp, err := tc.Get("/", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), http.StatusOK))
}
