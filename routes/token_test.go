package routes

import (
	"testing"

	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestTokenPasswordGrantJSON(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().PostForm("/auth/token", map[string]any{
		"grant_type": "password", "client_id": "spa", "username": "alice", "password": "right",
	})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	var cookie fasthttp.Cookie
	cookie.SetKey("__Secure-" + a.Config().CookieName)
	qt.Check(t, qt.IsTrue(resp.Header.Cookie(&cookie)))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(len(body) > 0))
}

func TestTokenPasswordGrantRedirect(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeRedirect,
	})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().PostForm("/auth/token", map[string]any{
		"grant_type": "password", "client_id": "ssr", "username": "alice", "password": "right", "return_to": "/dashboard",
	})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	// A POST redirect answers 303 See Other so the browser follows with a GET.
	qt.Check(t, qt.Equals(resp.StatusCode(), 303))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("Location")), "/dashboard"))
}

func TestTokenPasswordGrantRedirectRejectsOffOriginReturnTo(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeRedirect,
	})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	for _, returnTo := range []string{
		"https://evil.example/phish",
		"//evil.example/phish",
		"http:evil.example",
		"javascript:alert(1)",
		"/\\evil.example",
	} {
		resp, err := app.TestClient().PostForm("/auth/token", map[string]any{
			"grant_type": "password", "client_id": "ssr", "username": "alice", "password": "right", "return_to": returnTo,
		})
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(resp.StatusCode(), 303))

		loc := string(resp.Header.Peek("Location"))
		fasthttp.ReleaseResponse(resp)

		qt.Check(t, qt.Not(qt.StringContains(loc, "evil.example")))
		qt.Check(t, qt.Equals(loc, "/"))
	}
}

func TestTokenPasswordGrantCookie(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{
		ID: "cookie-app", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeCookie,
	})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().PostForm("/auth/token", map[string]any{
		"grant_type": "password", "client_id": "cookie-app", "username": "alice", "password": "right",
	})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 204))
}

func TestTokenPasswordGrantInvalidCredentials(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().PostForm("/auth/token", map[string]any{
		"grant_type": "password", "client_id": "spa", "username": "alice", "password": "wrong",
	})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 400))
}

func TestTokenUnsupportedGrantType(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{ID: "spa"})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().PostForm("/auth/token", map[string]any{
		"grant_type": "client_credentials", "client_id": "spa",
	})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 400))
}
