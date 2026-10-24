package routes

import (
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/apikey"
	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

func apiKeySPA() *client.Client {
	return &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	}
}

func TestAPIKeysLifecycle(t *testing.T) {
	a := newTestAuthWithOpts(t, session.NewMemoryStore(), []auth.Option{auth.APIKeyStore(apikey.NewMemoryStore())}, apiKeySPA())
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	bearer := tc.WithHeader("Authorization", "Bearer "+login.AccessToken)

	resp, err := tc.PostJSON("/auth/apikeys", map[string]any{"name": "ci", "scope": "profile", "expires_at": "2099-01-01T00:00:00Z"}, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 201))

	var created struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Scope     string `json:"scope"`
		ExpiresAt string `json:"expires_at"`
		Token     string `json:"token"`
	}

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &created)))
	fasthttp.ReleaseResponse(resp)

	qt.Check(t, qt.Equals(created.Name, "ci"))
	qt.Check(t, qt.Equals(created.Scope, "profile"))
	qt.Check(t, qt.Equals(created.ExpiresAt, "2099-01-01T00:00:00Z"))
	qt.Check(t, qt.StringContains(created.Token, "v4.local."))

	resp, err = tc.Get("/auth/apikeys", bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	body, err = resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(body), `"id":"`+created.ID+`"`))
	qt.Check(t, qt.Not(qt.StringContains(string(body), "token")))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.PostJSON("/auth/apikeys/"+created.ID+"/rotate", map[string]any{}, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	var rotated struct {
		ID        string `json:"id"`
		RotatedAt string `json:"rotated_at"`
		Token     string `json:"token"`
	}

	body, err = resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &rotated)))
	fasthttp.ReleaseResponse(resp)

	qt.Check(t, qt.Equals(rotated.ID, created.ID))
	qt.Check(t, qt.Not(qt.Equals(rotated.RotatedAt, "")))
	qt.Check(t, qt.Not(qt.Equals(rotated.Token, created.Token)))

	_, _, err = a.ValidateAPIKey(t.Context(), created.Token)
	qt.Check(t, qt.IsNotNil(err))

	created.Token = rotated.Token

	resp, err = tc.Delete("/auth/apikeys/"+created.ID, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 204))
	fasthttp.ReleaseResponse(resp)

	_, _, err = a.ValidateAPIKey(t.Context(), created.Token)
	qt.Check(t, qt.IsNotNil(err))

	// Keys never authenticate the key endpoints themselves.
	resp, err = tc.Get("/auth/apikeys", tc.WithHeader("Authorization", "Bearer "+created.Token))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 401))
}

func TestAPIKeysRevokeUnknown(t *testing.T) {
	a := newTestAuthWithOpts(t, session.NewMemoryStore(), []auth.Option{auth.APIKeyStore(apikey.NewMemoryStore())}, apiKeySPA())
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	resp, err := tc.Delete("/auth/apikeys/missing", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 404))
}

func TestAPIKeysNotMountedWithoutStore(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), apiKeySPA())
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	h := Bind(app, "/auth", a)
	qt.Check(t, qt.IsNil(h.APIKeys.List))

	tc := app.TestClient()

	resp, err := tc.Get("/auth/apikeys", tc.WithHeader("Authorization", "Bearer "+login.AccessToken))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 404))
}

func TestAPIKeysCreateRefusesCrossSiteCookie(t *testing.T) {
	a := newTestAuthWithOpts(t, session.NewMemoryStore(), []auth.Option{auth.APIKeyStore(apikey.NewMemoryStore())}, apiKeySPA())
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	resp, err := tc.PostJSON("/auth/apikeys", map[string]any{"name": "ci"},
		tc.WithCookie(a.Config().CookieName, login.Cookie.Value), tc.WithHeader("Sec-Fetch-Site", "cross-site"))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 403))
}

func TestChangePasswordFormFlagsAreBooleans(t *testing.T) {
	a, users := accountTestAuth(t, apiKeySPA(), auth.APIKeyStore(apikey.NewMemoryStore()))
	login := loginFor(t, a, "spa")

	res, err := a.CreateAPIKey(t.Context(), auth.CreateAPIKeyRequest{Token: login.AccessToken, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	bearer := tc.WithHeader("Authorization", "Bearer "+login.AccessToken)

	// "false" and "0" are not a request to revoke or keep; a bare checkbox's "on" is.
	other := loginFor(t, a, "spa")

	resp, err := tc.PostForm("/auth/account/password", map[string]any{"client_id": "spa", "current_password": "right", "new_password": "other123", "revoke_api_keys": "false", "keep_other_sessions": "0"}, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 204))
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(users.password, "other123"))

	_, _, err = a.ValidateAPIKey(t.Context(), res.Token)
	qt.Check(t, qt.IsNil(err))

	_, _, err = a.IntrospectToken(t.Context(), other.AccessToken)
	qt.Check(t, qt.IsNotNil(err))

	resp, err = tc.PostForm("/auth/account/password", map[string]any{"client_id": "spa", "current_password": "other123", "new_password": "third123", "revoke_api_keys": "on"}, bearer)
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 204))

	_, _, err = a.ValidateAPIKey(t.Context(), res.Token)
	qt.Check(t, qt.IsNotNil(err))
}
