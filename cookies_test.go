package auth

import (
	"testing"

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
			Name: "__session", Value: "tok", Path: "/", MaxAge: 3600,
			Secure: true, HTTPOnly: true, SameSite: "lax",
		})
		ctx.StatusCode(http.StatusNoContent)
	})

	resp, err := app.TestClient().Get("/")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	var cookie fasthttp.Cookie
	cookie.SetKey("__session")
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
		(&Auth{}).WriteCookie(ctx, &CookieDirective{Name: "__session", Path: "/", MaxAge: -1})
		ctx.StatusCode(http.StatusNoContent)
	})

	resp, err := app.TestClient().Get("/")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	var cookie fasthttp.Cookie
	cookie.SetKey("__session")
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
	cookie.SetKey("__session")
	qt.Check(t, qt.IsFalse(resp.Header.Cookie(&cookie)))
}

func TestReadSessionTokenPrefersBearer(t *testing.T) {
	a := &Auth{config: &Configuration{CookieName: "__session"}}

	app := azugo.NewTestApp()
	app.Start(t)
	defer app.Stop()

	app.Get("/", func(ctx *azugo.Context) {
		ctx.Text(a.ReadSessionToken(ctx))
	})

	tc := app.TestClient()
	resp, err := tc.Get("/", tc.WithHeader("Authorization", "Bearer from-header"), tc.WithCookie("__session", "from-cookie"))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(body), "from-header"))
}

func TestReadSessionTokenFallsBackToCookie(t *testing.T) {
	a := &Auth{config: &Configuration{CookieName: "__session"}}

	app := azugo.NewTestApp()
	app.Start(t)
	defer app.Stop()

	app.Get("/", func(ctx *azugo.Context) {
		ctx.Text(a.ReadSessionToken(ctx))
	})

	tc := app.TestClient()
	resp, err := tc.Get("/", tc.WithCookie("__session", "from-cookie"))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(body), "from-cookie"))
}

func TestReadSessionTokenEmpty(t *testing.T) {
	a := &Auth{config: &Configuration{CookieName: "__session"}}

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
