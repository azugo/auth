package middleware

import (
	"context"
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestRequireStepUpGuardsAppActions(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	}, auth.StepUp(auth.StepUpPolicyFunc(func(_ context.Context, _ *session.Session, action string) (auth.StepUpRequirement, bool) {
		return auth.StepUpRequirement{Methods: []string{"otp"}}, action == "account.delete"
	})))
	login := loginFor(t, a, "spa")

	app := newTestApp(t)

	danger := app.Group("/delete")
	danger.Use(RequireStepUp(a, "account.delete"))
	danger.Post("", func(ctx *azugo.Context) { ctx.StatusCode(http.StatusNoContent) })

	public := app.Group("/export")
	public.Use(RequireStepUp(a, "account.export"))
	public.Post("", func(ctx *azugo.Context) { ctx.StatusCode(http.StatusNoContent) })

	tc := app.TestClient()
	bearer := tc.WithHeader("Authorization", "Bearer "+login.AccessToken)

	resp, err := tc.Post("/delete", nil, bearer)
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), http.StatusUnauthorized))
	qt.Check(t, qt.Matches(string(resp.Header.Peek(http.HeaderWWWAuthenticate)), `.*insufficient_user_authentication.*`))

	// An action the policy does not name only needs an active session.
	resp2, err := tc.Post("/export", nil, bearer)
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp2.StatusCode(), http.StatusNoContent))

	resp3, err := tc.Post("/export", nil)
	defer fasthttp.ReleaseResponse(resp3)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp3.StatusCode(), http.StatusUnauthorized))
}
