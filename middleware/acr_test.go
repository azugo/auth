package middleware

import (
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/client"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestRequireACRGatesOnLadder(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	a.Config().ACRLevels = []auth.ACRLevelConfig{{Value: "loa1", Level: 1}, {Value: "loa2", Level: 2, RequireMFA: true}}

	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	app.Use(Auth(a))
	app.Use(RequireAuth())

	low := app.Group("/low")
	low.Use(RequireACR(a, "loa1"))
	low.Get("", func(ctx *azugo.Context) { ctx.Text(ctx.User().ClaimValue("acr")) })

	high := app.Group("/high")
	high.Use(RequireACR(a, "loa2"))
	high.Get("", func(ctx *azugo.Context) { ctx.Text("secret") })

	tc := app.TestClient()

	resp, err := tc.Get("/low", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), http.StatusOK))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(body), "loa1"))

	resp2, err := tc.Get("/high", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp2.StatusCode(), http.StatusForbidden))
}
