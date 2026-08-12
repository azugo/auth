package routes

import (
	"testing"

	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestUserInfoReturnsClaimsForValidBearer(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	resp, err := tc.Get("/auth/userinfo", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	doc := decodeJSON[struct {
		Subject string `json:"sub"`
		Name    string `json:"name"`
		Email   string `json:"email"`
	}](t, resp)
	qt.Check(t, qt.Equals(doc.Subject, "u1"))
	qt.Check(t, qt.Equals(doc.Name, "Alice"))
	qt.Check(t, qt.Equals(doc.Email, "alice@example.com"))
}

func TestUserInfoRejectsMissingToken(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{ID: "spa"})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().Get("/auth/userinfo")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 401))
}
