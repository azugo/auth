package routes

import (
	"testing"

	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestGetSessionKeepalive(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	resp, err := tc.Get("/auth/session", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	resp2, err := tc.Get("/auth/session")
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp2.StatusCode(), 401))
}

func TestDeleteSessionLogout(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	resp, err := tc.Delete("/auth/session", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 204))

	// The revoked session's access token no longer works.
	resp2, err := tc.Get("/auth/session", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp2.StatusCode(), 401))
}
