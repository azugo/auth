package routes

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/bcrypt"
)

// grantsTestClients returns the portal (password) and code-flow clients used by the
// authorization-code endpoint tests.
func grantsTestClients() (*client.Client, *client.Client) {
	portal := &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	}
	web := &client.Client{
		ID: "web", GrantTypes: []string{"authorization_code"},
		RedirectURIs: []string{"https://web.example/callback"},
		Public:       true, RequirePKCE: true,
		ResponseMode: client.ResponseModeJSON,
	}

	return portal, web
}

// RFC 7636 verifier/S256 challenge pair.
const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestAuthorizeEndpointRedirectsWithCode(t *testing.T) {
	portal, web := grantsTestClients()
	a := newTestAuth(t, session.NewMemoryStore(), portal, web)
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	resp, err := tc.Get("/auth/authorize?response_type=code&client_id=web"+
		"&redirect_uri="+url.QueryEscape("https://web.example/callback")+
		"&scope=openid&state=xyz&code_challenge="+pkceChallenge+"&code_challenge_method=S256",
		tc.WithHeader("Cookie", "__session="+login.Cookie.Value))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.Equals(resp.StatusCode(), 302))

	loc := string(resp.Header.Peek("Location"))
	qt.Check(t, qt.IsTrue(strings.HasPrefix(loc, "https://web.example/callback?")))

	u, err := url.Parse(loc)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(u.Query().Get("state"), "xyz"))
	qt.Assert(t, qt.IsTrue(u.Query().Get("code") != ""))
	settle()

	// Redeem the code at the token endpoint.
	resp2, err := tc.PostForm("/auth/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     "web",
		"code":          u.Query().Get("code"),
		"redirect_uri":  "https://web.example/callback",
		"code_verifier": pkceVerifier,
	})
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp2.StatusCode(), 200))

	var res auth.TokenResult

	qt.Assert(t, qt.IsNil(json.Unmarshal(resp2.Body(), &res)))
	qt.Check(t, qt.IsTrue(res.AccessToken != ""))
	qt.Check(t, qt.Equals(res.TokenType, "Bearer"))
}

func TestAuthorizeEndpointWithoutSessionIsLoginRequired(t *testing.T) {
	portal, web := grantsTestClients()
	a := newTestAuth(t, session.NewMemoryStore(), portal, web)

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	resp, err := tc.Get("/auth/authorize?response_type=code&client_id=web" +
		"&redirect_uri=" + url.QueryEscape("https://web.example/callback") +
		"&code_challenge=" + pkceChallenge + "&code_challenge_method=S256")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 401))
}

func TestRevokeEndpointReturnsOKForUnknownToken(t *testing.T) {
	portal, _ := grantsTestClients()
	a := newTestAuth(t, session.NewMemoryStore(), portal)

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	resp, err := tc.PostForm("/auth/revoke", map[string]any{
		"client_id": "spa",
		"token":     "garbage",
	})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))
}

func TestIntrospectEndpointRejectsPublicClient(t *testing.T) {
	portal, _ := grantsTestClients()
	a := newTestAuth(t, session.NewMemoryStore(), portal)

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	resp, err := tc.PostForm("/auth/introspect", map[string]any{
		"client_id": "spa",
		"token":     "whatever",
	})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 401))
}

func TestDiscoveryAdvertisesPhase4Endpoints(t *testing.T) {
	portal, _ := grantsTestClients()
	a := newTestAuth(t, session.NewMemoryStore(), portal)

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	resp, err := tc.Get("/auth/.well-known/openid-configuration")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	var doc struct {
		AuthorizationEndpoint         string   `json:"authorization_endpoint"`
		RevocationEndpoint            string   `json:"revocation_endpoint"`
		IntrospectionEndpoint         string   `json:"introspection_endpoint"`
		ResponseTypesSupported        []string `json:"response_types_supported"`
		CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
		TokenAuthMethods              []string `json:"token_endpoint_auth_methods_supported"`
	}

	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &doc)))
	qt.Check(t, qt.Equals(doc.AuthorizationEndpoint, "https://issuer.example/authorize"))
	qt.Check(t, qt.Equals(doc.RevocationEndpoint, "https://issuer.example/revoke"))
	qt.Check(t, qt.Equals(doc.IntrospectionEndpoint, "https://issuer.example/introspect"))
	qt.Check(t, qt.DeepEquals(doc.ResponseTypesSupported, []string{"code"}))
	qt.Check(t, qt.DeepEquals(doc.CodeChallengeMethodsSupported, []string{"S256"}))
	qt.Check(t, qt.DeepEquals(doc.TokenAuthMethods, []string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt"}))
}

func TestTokenEndpointResponseIsNotCacheable(t *testing.T) {
	portal, web := grantsTestClients()
	a := newTestAuth(t, session.NewMemoryStore(), portal, web)
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	resp, err := tc.Get("/auth/authorize?response_type=code&client_id=web"+
		"&redirect_uri="+url.QueryEscape("https://web.example/callback")+
		"&code_challenge="+pkceChallenge+"&code_challenge_method=S256",
		tc.WithHeader("Cookie", "__session="+login.Cookie.Value))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	u, err := url.Parse(string(resp.Header.Peek("Location")))
	qt.Assert(t, qt.IsNil(err))
	settle()

	resp2, err := tc.PostForm("/auth/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     "web",
		"code":          u.Query().Get("code"),
		"redirect_uri":  "https://web.example/callback",
		"code_verifier": pkceVerifier,
	})
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp2.StatusCode(), 200))
	qt.Check(t, qt.Equals(string(resp2.Header.Peek("Cache-Control")), "no-store"))
	qt.Check(t, qt.Equals(string(resp2.Header.Peek("Pragma")), "no-cache"))
}

// confidentialClient returns a client_secret client for Basic-auth endpoint tests.
func confidentialClient(t *testing.T, id, secret string) *client.Client {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	qt.Assert(t, qt.IsNil(err))

	return &client.Client{
		ID: id, SecretHash: string(hash),
		TokenEndpointAuthMethod: client.TokenEndpointAuthClientSecret,
	}
}

func TestIntrospectEndpointAcceptsBasicClientAuth(t *testing.T) {
	portal, _ := grantsTestClients()
	rs := confidentialClient(t, "svc", "s3cret")
	a := newTestAuth(t, session.NewMemoryStore(), portal, rs)
	login := loginFor(t, a, "spa")

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	basic := base64.StdEncoding.EncodeToString([]byte("svc:s3cret"))

	resp, err := tc.PostForm("/auth/introspect", map[string]any{
		"token": login.AccessToken,
	}, tc.WithHeader("Authorization", "Basic "+basic))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	var out auth.IntrospectionResponse

	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	qt.Check(t, qt.IsTrue(out.Active))
	qt.Check(t, qt.Equals(out.ClientID, "spa"))
}

func TestIntrospectEndpointRejectsMixedClientAuth(t *testing.T) {
	portal, _ := grantsTestClients()
	rs := confidentialClient(t, "svc", "s3cret")
	a := newTestAuth(t, session.NewMemoryStore(), portal, rs)

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	basic := base64.StdEncoding.EncodeToString([]byte("svc:s3cret"))

	resp, err := tc.PostForm("/auth/introspect", map[string]any{
		"client_id":     "svc",
		"client_secret": "s3cret",
		"token":         "whatever",
	}, tc.WithHeader("Authorization", "Basic "+basic))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 400))
}
