package auth

import (
	"testing"

	"azugo.io/auth/internal/dpoptest"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestWriteCookieSet(t *testing.T) {
	app := azugo.NewTestApp()
	app.Start(t)
	defer app.Stop()

	app.Get("/", func(ctx *azugo.Context) {
		(&Auth{}).WriteCookie(ctx, &CookieDirective{
			Name: "session", Value: "tok", Path: "/", MaxAge: 3600,
			SameSite: azugo.CookieSameSiteLax,
		})
		ctx.StatusCode(http.StatusNoContent)
	})

	resp, err := app.TestClient().Get("/")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	var cookie fasthttp.Cookie
	cookie.SetKey("__Host-session")
	qt.Assert(t, qt.IsTrue(resp.Header.Cookie(&cookie)))
	qt.Check(t, qt.Equals(string(cookie.Value()), "tok"))
	qt.Check(t, qt.Equals(string(cookie.Path()), "/"))
	qt.Check(t, qt.IsTrue(cookie.Secure()))
	qt.Check(t, qt.IsTrue(cookie.HTTPOnly()))
	qt.Check(t, qt.Equals(cookie.SameSite(), fasthttp.CookieSameSiteLaxMode))
	qt.Check(t, qt.Equals(cookie.MaxAge(), 3600))
}

func TestWriteCookieClear(t *testing.T) {
	app := azugo.NewTestApp()
	app.Start(t)
	defer app.Stop()

	app.Get("/", func(ctx *azugo.Context) {
		(&Auth{}).WriteCookie(ctx, &CookieDirective{Name: "session", Path: "/", MaxAge: -1})
		ctx.StatusCode(http.StatusNoContent)
	})

	resp, err := app.TestClient().Get("/")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	var cookie fasthttp.Cookie
	cookie.SetKey("__Host-session")
	qt.Assert(t, qt.IsTrue(resp.Header.Cookie(&cookie)))
	qt.Check(t, qt.IsTrue(cookie.Expire().Equal(fasthttp.CookieExpireDelete)))
}

func TestWriteCookieNilIsNoop(t *testing.T) {
	app := azugo.NewTestApp()
	app.Start(t)
	defer app.Stop()

	app.Get("/", func(ctx *azugo.Context) {
		(&Auth{}).WriteCookie(ctx, nil)
		ctx.StatusCode(http.StatusNoContent)
	})

	resp, err := app.TestClient().Get("/")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	var cookie fasthttp.Cookie
	cookie.SetKey("session")
	qt.Check(t, qt.IsFalse(resp.Header.Cookie(&cookie)))
}

func TestReadSessionTokenPrefersBearer(t *testing.T) {
	a := &Auth{config: &Configuration{CookieName: "session"}}

	app := azugo.NewTestApp()
	app.Start(t)
	defer app.Stop()

	app.Get("/", func(ctx *azugo.Context) {
		ctx.Text(a.ReadSessionToken(ctx))
	})

	tc := app.TestClient()
	resp, err := tc.Get("/", tc.WithHeader("Authorization", "Bearer from-header"), tc.WithCookie("session", "from-cookie"))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(body), "from-header"))
}

func TestReadSessionTokenFallsBackToCookie(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient())
	login := dpopLogin(t, a, dpoptest.NewKey(t))

	app := azugo.NewTestApp()
	app.Start(t)
	defer app.Stop()

	app.Get("/", func(ctx *azugo.Context) {
		ctx.Text(a.ReadSessionToken(ctx))
	})

	tc := app.TestClient()

	// Only a session cookie is read from the cookie; a bound access token there is no bearer token.
	for name, tt := range map[string]struct{ cookie, want string }{
		"session cookie": {login.Cookie.Value, login.Cookie.Value},
		"bound token":    {login.AccessToken, ""},
		"garbage":        {"from-cookie", ""},
	} {
		resp, err := tc.Get("/", tc.WithCookie(a.config.CookieName, tt.cookie))
		qt.Assert(t, qt.IsNil(err))

		body, err := resp.BodyUncompressed()
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(string(body), tt.want), qt.Commentf(name))
		fasthttp.ReleaseResponse(resp)
	}
}

func TestReadSessionTokenEmpty(t *testing.T) {
	a := &Auth{config: &Configuration{CookieName: "session"}}

	app := azugo.NewTestApp()
	app.Start(t)
	defer app.Stop()

	app.Get("/", func(ctx *azugo.Context) {
		ctx.Text(a.ReadSessionToken(ctx))
	})

	resp, err := app.TestClient().Get("/")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(body), ""))
}
