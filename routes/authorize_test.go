package routes

import (
	"testing"

	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestAuthorizeSilentRefreshRotatesCookie(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeCookie,
	})
	login := loginFor(t, a, "ssr")

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	resp, err := tc.Post("/auth/authorize", nil, tc.WithCookie(a.Config().CookieName, login.Cookie.Value))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 204))

	var cookie fasthttp.Cookie
	cookie.SetKey(a.Config().CookieName)
	qt.Assert(t, qt.IsTrue(resp.Header.Cookie(&cookie)))
	qt.Check(t, qt.Not(qt.Equals(string(cookie.Value()), login.Cookie.Value)))
}

func TestAuthorizeSilentRefreshWithoutCookieFails(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{ID: "ssr"})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().Post("/auth/authorize", nil)
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 401))
}
