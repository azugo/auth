package routes

import (
	"strings"
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/client"
	"azugo.io/auth/internal/dpoptest"
	"azugo.io/auth/middleware"
	"azugo.io/auth/session"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

const (
	testTokenURL    = "http://test/auth/token"
	testUserInfoURL = "http://test/auth/userinfo"
)

func dpopClient() *client.Client {
	return &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	}
}

func TestTokenEndpointIssuesDPoPBoundToken(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), dpopClient())

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	key := dpoptest.NewKey(t)

	resp, err := tc.PostForm("/auth/token", map[string]any{
		"grant_type": "password", "client_id": "spa", "username": "alice", "password": "right",
	}, tc.WithHeader("DPoP", key.Proof(t, "POST", testTokenURL, nil)))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}

	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	qt.Check(t, qt.Equals(out.TokenType, "DPoP"))

	// A bound token is no bearer token.
	resp, err = tc.Get("/auth/userinfo", tc.WithHeader("Authorization", "Bearer "+out.AccessToken))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 401))
	fasthttp.ReleaseResponse(resp)

	proof := key.AccessProof(t, "GET", testUserInfoURL, out.AccessToken)

	resp, err = tc.Get("/auth/userinfo", tc.WithHeader("Authorization", "DPoP "+out.AccessToken), tc.WithHeader("DPoP", proof))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))
	fasthttp.ReleaseResponse(resp)

	// A proof is single use.
	resp, err = tc.Get("/auth/userinfo", tc.WithHeader("Authorization", "DPoP "+out.AccessToken), tc.WithHeader("DPoP", proof))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 401))
	fasthttp.ReleaseResponse(resp)

	// A proof by another key does not hold the token.
	other := dpoptest.NewKey(t).AccessProof(t, "GET", testUserInfoURL, out.AccessToken)

	resp, err = tc.Get("/auth/userinfo", tc.WithHeader("Authorization", "DPoP "+out.AccessToken), tc.WithHeader("DPoP", other))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 401))
	fasthttp.ReleaseResponse(resp)
}

func TestUserInfoRefusesAccessTokenCookie(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), dpopClient())

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	key := dpoptest.NewKey(t)

	bound, err := a.Login(t.Context(), auth.LoginRequest{
		Credentials: auth.ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "right",
		DPoP: &auth.DPoPProof{Proof: key.Proof(t, "POST", testTokenURL, nil), Method: "POST", URL: testTokenURL},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(bound.TokenType, "DPoP"))

	bearer := loginFor(t, a, "spa")

	// The cookie slot carries the session cookie only; an access token there needs no proof and is refused.
	for name, tt := range map[string]struct {
		cookie string
		want   int
	}{
		"session cookie": {bound.Cookie.Value, 200},
		"bound token":    {bound.AccessToken, 401},
		"bearer token":   {bearer.AccessToken, 401},
	} {
		resp, err := tc.Get("/auth/userinfo", tc.WithCookie(a.Config().CookieName, tt.cookie))
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(resp.StatusCode(), tt.want), qt.Commentf(name))
		fasthttp.ReleaseResponse(resp)
	}
}

func TestUserInfoChallengesWithDPoP(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), dpopClient())

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	key := dpoptest.NewKey(t)

	bound, err := a.Login(t.Context(), auth.LoginRequest{
		Credentials: auth.ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "right",
		DPoP: &auth.DPoPProof{Proof: key.Proof(t, "POST", testTokenURL, nil), Method: "POST", URL: testTokenURL},
	})
	qt.Assert(t, qt.IsNil(err))

	bearer := loginFor(t, a, "spa")

	// A credential failing its binding is answered with the RFC 9449 challenge.
	for name, tt := range map[string]struct {
		opts []azugo.TestClientOption
		code string
	}{
		"bound as bearer":    {[]azugo.TestClientOption{tc.WithHeader("Authorization", "Bearer "+bound.AccessToken)}, "invalid_token"},
		"missing proof":      {[]azugo.TestClientOption{tc.WithHeader("Authorization", "DPoP "+bound.AccessToken)}, "invalid_dpop_proof"},
		"unbound as dpop":    {[]azugo.TestClientOption{tc.WithHeader("Authorization", "DPoP "+bearer.AccessToken), tc.WithHeader("DPoP", key.AccessProof(t, "GET", testUserInfoURL, bearer.AccessToken))}, "invalid_token"},
		"proof by other key": {[]azugo.TestClientOption{tc.WithHeader("Authorization", "DPoP "+bound.AccessToken), tc.WithHeader("DPoP", dpoptest.NewKey(t).AccessProof(t, "GET", testUserInfoURL, bound.AccessToken))}, "invalid_dpop_proof"},
	} {
		resp, err := tc.Get("/auth/userinfo", tt.opts...)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(resp.StatusCode(), 401), qt.Commentf(name))

		challenge := string(resp.Header.Peek("WWW-Authenticate"))
		qt.Check(t, qt.IsTrue(strings.HasPrefix(challenge, "DPoP ")), qt.Commentf("%s: %s", name, challenge))
		qt.Check(t, qt.StringContains(challenge, `error="`+tt.code+`"`), qt.Commentf(name))
		fasthttp.ReleaseResponse(resp)
	}

	// A proof by the token's key is checked once, by the middleware; the handler reads the token.
	resp, err := tc.Get("/auth/userinfo", tc.WithHeader("Authorization", "DPoP "+bound.AccessToken), tc.WithHeader("DPoP", key.AccessProof(t, "GET", testUserInfoURL, bound.AccessToken)))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))
}

func TestTokenEndpointDPoPPolicyRequired(t *testing.T) {
	cl := dpopClient()
	cl.DPoPPolicy = client.DPoPPolicyRequired
	a := newTestAuth(t, session.NewMemoryStore(), cl)

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().PostForm("/auth/token", map[string]any{
		"grant_type": "password", "client_id": "spa", "username": "alice", "password": "right",
	})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 400))
	qt.Check(t, qt.StringContains(string(resp.Body()), "invalid_dpop_proof"))
}

func TestTokenEndpointRefusesMultipleProofs(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), dpopClient())

	app := newTestApp(t)
	Bind(app, "/auth", a)

	key := dpoptest.NewKey(t)

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(testTokenURL)
	req.Header.SetMethod("POST")
	req.Header.SetContentType("application/x-www-form-urlencoded")
	req.Header.Add("DPoP", key.Proof(t, "POST", testTokenURL, nil))
	req.Header.Add("DPoP", key.Proof(t, "POST", testTokenURL, nil))
	req.SetBodyString("grant_type=password&client_id=spa&username=alice&password=right")

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.IsNil(app.TestClient().Client().Do(req, resp)))
	qt.Check(t, qt.Equals(resp.StatusCode(), 400))
	qt.Check(t, qt.StringContains(string(resp.Body()), "invalid_dpop_proof"))
}

func TestTokenEndpointDPoPNonce(t *testing.T) {
	cl := dpopClient()
	cl.DPoPPolicy = client.DPoPPolicyNonce
	a := newTestAuth(t, session.NewMemoryStore(), cl)

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	key := dpoptest.NewKey(t)
	form := map[string]any{"grant_type": "password", "client_id": "spa", "username": "alice", "password": "right"}

	// A cold-start client gets the nonce with the refusal of its proof-less request.
	resp, err := tc.PostForm("/auth/token", form)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 400))
	qt.Check(t, qt.StringContains(string(resp.Body()), "invalid_dpop_proof"))
	qt.Check(t, qt.Not(qt.Equals(string(resp.Header.Peek("DPoP-Nonce")), "")))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.PostForm("/auth/token", form, tc.WithHeader("DPoP", key.Proof(t, "POST", testTokenURL, nil)))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 400))
	qt.Check(t, qt.StringContains(string(resp.Body()), "use_dpop_nonce"))

	nonce := string(resp.Header.Peek("DPoP-Nonce"))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Not(qt.Equals(nonce, "")))

	resp, err = tc.PostForm("/auth/token", form, tc.WithHeader("DPoP", key.Proof(t, "POST", testTokenURL, map[string]any{"nonce": nonce})))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("DPoP-Nonce")), nonce))
}

func TestDiscoveryAdvertisesDPoP(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), dpopClient())

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().Get("/auth/.well-known/openid-configuration")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	var doc struct {
		DPoPAlgs []string `json:"dpop_signing_alg_values_supported"`
	}

	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &doc)))
	qt.Check(t, qt.SliceContains(doc.DPoPAlgs, "ES256"))
}

func TestBindBeforeGlobalAuthVerifiesProofOnce(t *testing.T) {
	for name, tt := range map[string]struct {
		bindFirst bool
		status    int
	}{
		// Use wraps only the routes registered after it, so /auth keeps its own DPoP middleware.
		"bind first": {true, 200},
		// Auth above Bind verifies the single-use proof twice; the second sees the replay.
		"auth first": {false, 401},
	} {
		t.Run(name, func(t *testing.T) {
			a := newTestAuth(t, session.NewMemoryStore(), dpopClient())

			app := newTestApp(t)
			if tt.bindFirst {
				Bind(app, "/auth", a)
			}

			app.Use(middleware.Auth(a, middleware.Cookie()))

			if !tt.bindFirst {
				Bind(app, "/auth", a)
			}

			tc := app.TestClient()
			key := dpoptest.NewKey(t)

			bound, err := a.Login(t.Context(), auth.LoginRequest{
				Credentials: auth.ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "right",
				DPoP: &auth.DPoPProof{Proof: key.Proof(t, "POST", testTokenURL, nil), Method: "POST", URL: testTokenURL},
			})
			qt.Assert(t, qt.IsNil(err))

			resp, err := tc.Get("/auth/userinfo", tc.WithHeader("Authorization", "DPoP "+bound.AccessToken), tc.WithHeader("DPoP", key.AccessProof(t, "GET", testUserInfoURL, bound.AccessToken)))
			defer fasthttp.ReleaseResponse(resp)
			qt.Assert(t, qt.IsNil(err))
			qt.Check(t, qt.Equals(resp.StatusCode(), tt.status), qt.Commentf("%s", resp.Header.Peek("WWW-Authenticate")))
		})
	}
}
