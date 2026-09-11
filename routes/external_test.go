package routes

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/provider"
	"azugo.io/auth/session"

	"azugo.io/core"
	"azugo.io/core/config"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

type fakeExtProvider struct{}

func (fakeExtProvider) AuthURL(_ context.Context, state, nonce, codeChallenge string) (string, error) {
	q := url.Values{"state": {state}, "nonce": {nonce}, "code_challenge": {codeChallenge}}

	return "https://idp.example/authorize?" + q.Encode(), nil
}

func (fakeExtProvider) Exchange(_ context.Context, code, _, _ string) (*provider.Tokens, error) {
	return &provider.Tokens{
		IDToken:   "idt-" + code,
		RawClaims: map[string]any{"sub": "ext-1", "name": "Ext Alice", "email": "ext@example.com", "scp": "openid"},
	}, nil
}

type fakeExtDriver struct{}

func (fakeExtDriver) Open(*contract.ExternalProviderConfig) (provider.Provider, error) {
	return fakeExtProvider{}, nil
}

func (fakeExtDriver) DefaultClaimMapper() provider.ClaimMapper {
	return provider.ClaimMapperFunc(provider.MapStandardClaims)
}

func init() {
	provider.Register("fake", fakeExtDriver{})
}

// extUsers resolves any user ID so externally-created sessions introspect.
type extUsers struct{}

func (extUsers) Authenticate(_ context.Context, _, password string) (auth.UserInfo, error) {
	if password == "wrong" {
		return auth.UserInfo{}, auth.ErrInvalidCredentials
	}

	return auth.UserInfo{ID: "u1", Name: "Alice", Scope: "openid"}, nil
}

func (extUsers) GetUser(_ context.Context, id string) (auth.UserInfo, error) {
	return auth.UserInfo{ID: id, Name: "Ext Alice", Scope: "openid"}, nil
}

func newExternalTestAuth(t *testing.T, opts ...auth.Option) *auth.Auth {
	t.Helper()

	app := core.New()

	conf := config.New()
	qt.Assert(t, qt.IsNil(conf.Load(nil, conf, string(app.Env()))))
	app.SetConfig(nil, conf)
	t.Cleanup(app.Stop)

	cfg := &auth.Configuration{
		Secret:                  "0123456789abcdef0123456789abcdef",
		SameSite:                "strict",
		Issuer:                  "https://issuer.example/auth",
		LogoutInvalidatesCookie: true,
		Providers: []auth.ExternalProviderConfig{
			{Name: "corp", Driver: "fake", ClientID: "app-client", RedirectURL: "https://issuer.example/auth/external/corp/callback"},
		},
	}

	cl := &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		ResponseMode: client.ResponseModeRedirect,
	}

	a, err := auth.New(app, cfg, extUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry(cl), opts...)
	qt.Assert(t, qt.IsNil(err))

	return a
}

func TestExternalLoginRouteRedirectsToIdP(t *testing.T) {
	a := newExternalTestAuth(t)
	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	resp, err := tc.Get("/auth/external/corp/login?client_id=ssr&return_to=/home")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 302))

	loc := string(resp.Header.Peek("Location"))
	qt.Check(t, qt.IsTrue(strings.HasPrefix(loc, "https://idp.example/authorize?")))

	// Unknown provider names 404.
	resp2, err := tc.Get("/auth/external/nope/login?client_id=ssr")
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp2.StatusCode(), 404))
}

func TestExternalCallbackRouteCreatesSession(t *testing.T) {
	a := newExternalTestAuth(t)
	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	resp, err := tc.Get("/auth/external/corp/login?client_id=ssr&return_to=/home")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	u, err := url.Parse(string(resp.Header.Peek("Location")))
	qt.Assert(t, qt.IsNil(err))

	state := u.Query().Get("state")
	qt.Assert(t, qt.IsTrue(state != ""))

	settle()

	resp2, err := tc.Get("/auth/external/corp/callback?state=" + url.QueryEscape(state) + "&code=c1")
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp2.StatusCode(), 302))

	qt.Check(t, qt.Equals(string(resp2.Header.Peek("Location")), "/home"))
	qt.Check(t, qt.StringContains(string(resp2.Header.Peek("Set-Cookie")), "__session="))
}

func TestLogoutRouteClearsCookieAndRedirects(t *testing.T) {
	a := newExternalTestAuth(t)
	app := newTestApp(t)
	Bind(app, "/auth", a)

	login, err := a.Login(context.Background(), auth.LoginRequest{ClientID: "ssr", Username: "alice", Password: "right"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	tc := app.TestClient()

	resp, err := tc.Get("/auth/logout", tc.WithHeader("Cookie", "__session="+login.Cookie.Value))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 302))

	qt.Check(t, qt.Equals(string(resp.Header.Peek("Location")), "/"))
	qt.Check(t, qt.StringContains(string(resp.Header.Peek("Set-Cookie")), "__session=;"))

	settle()

	_, _, err = a.IntrospectToken(context.Background(), login.Cookie.Value)
	qt.Check(t, qt.IsNotNil(err))
}

func TestLinkingRoutesRequireIdentityStore(t *testing.T) {
	// Without an IdentityStore the linking surface is not mounted.
	a := newExternalTestAuth(t)
	app := newTestApp(t)
	h := Bind(app, "/auth", a)
	qt.Check(t, qt.IsNil(h.External.Link))

	tc := app.TestClient()

	resp, err := tc.Get("/auth/external/identities")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 404))

	// With one it is mounted by default.
	a2 := newExternalTestAuth(t, auth.IdentityStore(provider.NewMemoryIdentityStore()))
	app2 := newTestApp(t)
	h2 := Bind(app2, "/auth", a2)
	qt.Check(t, qt.IsNotNil(h2.External.Link))

	login, err := a2.Login(context.Background(), auth.LoginRequest{ClientID: "ssr", Username: "alice", Password: "right"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	tc2 := app2.TestClient()

	resp2, err := tc2.Get("/auth/external/identities", tc2.WithHeader("Cookie", "__session="+login.Cookie.Value))
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp2.StatusCode(), 200))

	// The linking ceremony starts an IdP redirect for the authenticated caller.
	resp3, err := tc2.Get("/auth/external/corp/link", tc2.WithHeader("Cookie", "__session="+login.Cookie.Value))
	defer fasthttp.ReleaseResponse(resp3)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp3.StatusCode(), 302))
	qt.Check(t, qt.IsTrue(strings.HasPrefix(string(resp3.Header.Peek("Location")), "https://idp.example/authorize?")))
}

func TestExternalLinkCallbackReturnToPrefixesBasePath(t *testing.T) {
	t.Setenv("BASE_PATH", "/app")

	a := newExternalTestAuth(t, auth.IdentityStore(provider.NewMemoryIdentityStore()))
	app := newTestApp(t)
	Bind(app, "/auth", a)

	login, err := a.Login(context.Background(), auth.LoginRequest{ClientID: "ssr", Username: "alice", Password: "right"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	tc := app.TestClient()

	resp, err := tc.Get("/app/auth/external/corp/link?return_to=/profile", tc.WithHeader("Cookie", "__session="+login.Cookie.Value))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 302))

	u, err := url.Parse(string(resp.Header.Peek("Location")))
	qt.Assert(t, qt.IsNil(err))
	settle()

	resp2, err := tc.Get("/app/auth/external/corp/callback?state=" + url.QueryEscape(u.Query().Get("state")) + "&code=c1")
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp2.StatusCode(), 302))

	// ctx.Redirect prefixes BasePath; RedirectUnsafe would have emitted a bare "/profile".
	qt.Check(t, qt.Equals(string(resp2.Header.Peek("Location")), "/app/profile"))
}

func TestDiscoveryAdvertisesEndSessionEndpoint(t *testing.T) {
	a := newExternalTestAuth(t)
	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	resp, err := tc.Get("/auth/.well-known/openid-configuration")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	qt.Check(t, qt.StringContains(string(resp.Body()), `"end_session_endpoint":"https://issuer.example/auth/logout"`))
}
