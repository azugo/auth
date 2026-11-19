package routes

import (
	"context"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
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

func TestSessionActivity(t *testing.T) {
	store := session.NewMemoryStore()
	a := newTestAuth(t, store, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	a.Config().SessionIdleTTL = 30 * time.Minute
	login := loginFor(t, a, "spa")

	ctx := context.Background()
	_, sess, err := a.IntrospectToken(ctx, login.AccessToken)
	qt.Assert(t, qt.IsNil(err))

	sess.IdleExpiresAt = time.Now().Add(time.Minute).Truncate(time.Second)
	qt.Assert(t, qt.IsNil(store.Update(ctx, sess)))

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	bearer := tc.WithHeader("Authorization", "Bearer "+login.AccessToken)

	var got struct {
		ExpiresAt     time.Time `json:"expires_at"`
		IdleExpiresAt time.Time `json:"idle_expires_at"`
	}

	// Reading the lifetime does not count as activity.
	resp, err := tc.Get("/auth/session", bearer)
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &got)))
	qt.Check(t, qt.IsTrue(got.IdleExpiresAt.Equal(sess.IdleExpiresAt)))
	qt.Check(t, qt.IsTrue(got.ExpiresAt.Equal(sess.ExpiresAt)))

	resp2, err := tc.Post("/auth/session/activity", nil, bearer)
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp2.StatusCode(), 200))
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp2.Body(), &got)))
	qt.Check(t, qt.IsTrue(time.Until(got.IdleExpiresAt) > 29*time.Minute))

	// A same-origin request without a credential is refused, a cross-site one before that.
	resp3, err := tc.Post("/auth/session/activity", nil, tc.WithHeader("Sec-Fetch-Site", "same-origin"))
	defer fasthttp.ReleaseResponse(resp3)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp3.StatusCode(), 401))

	resp4, err := tc.Post("/auth/session/activity", nil, tc.WithHeader("Sec-Fetch-Site", "cross-site"))
	defer fasthttp.ReleaseResponse(resp4)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp4.StatusCode(), 403))
}

func TestSessionCookieIsReadOnlyUnderItsOwnName(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	// Scoped to the /auth mount, the cookie is written as __Secure-session; a bare or __Host-
	// variant another site planted is not read in its place.
	for name, want := range map[string]int{
		"session":          401,
		"__Host-session":   401,
		"__Secure-session": 200,
	} {
		resp, err := tc.Get("/auth/session", tc.WithCookie(name, login.Cookie.Value))
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(resp.StatusCode(), want), qt.Commentf("%s", name))
		fasthttp.ReleaseResponse(resp)
	}
}
