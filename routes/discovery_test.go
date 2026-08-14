package routes

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/core"
	"azugo.io/core/config"
	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

// genRSAPEM generates a fresh RSA key pair PEM-encoded as PKCS#8 (private) / PKIX (public).
func genRSAPEM(t *testing.T) (priv, pub string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	qt.Assert(t, qt.IsNil(err))

	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	qt.Assert(t, qt.IsNil(err))

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	qt.Assert(t, qt.IsNil(err))

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
}

func decodeJSON[T any](t *testing.T, resp *fasthttp.Response) T {
	t.Helper()

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	var v T
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &v)))

	return v
}

type discoveryDoc struct {
	Issuer                            string   `json:"issuer"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
}

func TestDiscoveryIntrospectOnlyOmitsJWTFields(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{ID: "spa"})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().Get("/auth/.well-known/openid-configuration")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	doc := decodeJSON[discoveryDoc](t, resp)
	qt.Check(t, qt.Equals(doc.Issuer, "https://issuer.example"))
	qt.Check(t, qt.Equals(doc.TokenEndpoint, "https://issuer.example/token"))
	qt.Check(t, qt.Equals(doc.UserinfoEndpoint, "https://issuer.example/userinfo"))
	qt.Check(t, qt.Equals(doc.JWKSURI, ""))
	qt.Check(t, qt.HasLen(doc.ScopesSupported, 0))
	qt.Check(t, qt.HasLen(doc.IDTokenSigningAlgValuesSupported, 0))
	// client_credentials requires a KeyProvider (JWT access tokens) and is not advertised
	// without one.
	qt.Check(t, qt.DeepEquals(doc.GrantTypesSupported, []string{"authorization_code", client.GrantTypePassword}))
	qt.Check(t, qt.DeepEquals(doc.SubjectTypesSupported, []string{"public"}))
}

func TestDiscoveryWithKeyProviderIncludesJWKSAndAlgorithms(t *testing.T) {
	priv, pub := genRSAPEM(t)
	opts := []auth.Option{auth.KeyProvider(mustKeyProvider(t, priv, pub))}

	a := newTestAuthWithOpts(t, session.NewMemoryStore(), opts, &client.Client{ID: "spa"})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().Get("/auth/.well-known/openid-configuration")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	doc := decodeJSON[discoveryDoc](t, resp)
	qt.Check(t, qt.Equals(doc.JWKSURI, "https://issuer.example/.well-known/jwks.json"))
	qt.Check(t, qt.DeepEquals(doc.ScopesSupported, []string{"openid"}))
	qt.Check(t, qt.DeepEquals(doc.IDTokenSigningAlgValuesSupported, []string{"RS256"}))
	qt.Check(t, qt.DeepEquals(doc.GrantTypesSupported, []string{"authorization_code", "client_credentials", client.GrantTypePassword}))
}

func mustKeyProvider(t *testing.T, priv, pub string) token.KeyProvider {
	t.Helper()

	kp, err := token.NewConfigKeyProvider(&contract.KeySetConfig{
		Primary: contract.KeyConfig{ID: "k1", Algorithm: "RS256", PrivateKey: priv, PublicKey: pub},
	})
	qt.Assert(t, qt.IsNil(err))

	return kp
}

func TestDiscoveryDerivesIssuerFromBindMountPrefix(t *testing.T) {
	app := core.New()

	conf := config.New()
	qt.Assert(t, qt.IsNil(conf.Load(nil, conf, string(app.Env()))))
	app.SetConfig(nil, conf)
	t.Cleanup(app.Stop)

	cfg := &auth.Configuration{
		Secret:                  "0123456789abcdef0123456789abcdef",
		SameSite:                "strict",
		LogoutInvalidatesCookie: true,
		// Issuer/BaseURL deliberately unset - the issuer must come from Bind's own prefix.
	}

	a, err := auth.New(app, cfg, stubUsers{info: auth.UserInfo{ID: "u1"}}, session.NewMemoryStore(),
		client.NewMemoryRegistry(&client.Client{ID: "spa"}))
	qt.Assert(t, qt.IsNil(err))

	testApp := newTestApp(t)
	Bind(testApp, "/api/auth", a)

	resp, err := testApp.TestClient().Get("/api/auth/.well-known/openid-configuration")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	doc := decodeJSON[discoveryDoc](t, resp)
	qt.Check(t, qt.Equals(doc.Issuer, "http://test/api/auth"))
	qt.Check(t, qt.Equals(doc.TokenEndpoint, "http://test/api/auth/token"))
	qt.Check(t, qt.Equals(doc.UserinfoEndpoint, "http://test/api/auth/userinfo"))
}

func TestDiscoveryManualMountUsesMountPrefixOption(t *testing.T) {
	app := core.New()

	conf := config.New()
	qt.Assert(t, qt.IsNil(conf.Load(nil, conf, string(app.Env()))))
	app.SetConfig(nil, conf)
	t.Cleanup(app.Stop)

	cfg := &auth.Configuration{
		Secret:                  "0123456789abcdef0123456789abcdef",
		SameSite:                "strict",
		LogoutInvalidatesCookie: true,
		// Issuer/BaseURL deliberately unset - MountPrefix must supply the prefix instead.
	}

	a, err := auth.New(app, cfg, stubUsers{info: auth.UserInfo{ID: "u1"}}, session.NewMemoryStore(),
		client.NewMemoryRegistry(&client.Client{ID: "spa"}))
	qt.Assert(t, qt.IsNil(err))

	h := New(a, MountPrefix("/api/auth"))

	testApp := newTestApp(t)
	testApp.Get("/api/auth/.well-known/openid-configuration", h.OIDC.Discovery)

	resp, err := testApp.TestClient().Get("/api/auth/.well-known/openid-configuration")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	doc := decodeJSON[discoveryDoc](t, resp)
	qt.Check(t, qt.Equals(doc.Issuer, "http://test/api/auth"))
	qt.Check(t, qt.Equals(doc.TokenEndpoint, "http://test/api/auth/token"))
	qt.Check(t, qt.Equals(doc.UserinfoEndpoint, "http://test/api/auth/userinfo"))
}

// TestDiscoveryEndpointOverridesTrackBaseURLUnlessAbsolute proves a relative-path override
// still resolves against the per-request base URL - like the default derivation does - while an
// absolute override is deliberately frozen, for genuinely cross-origin endpoints.
func TestDiscoveryEndpointOverridesTrackBaseURLUnlessAbsolute(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{ID: "spa"})

	h := New(a,
		TokenEndpoint("/oauth2/token"),
		UserinfoEndpoint("https://gateway.example/oauth2/userinfo"),
	)

	app := newTestApp(t)
	app.Get("/discovery", h.OIDC.Discovery)

	resp, err := app.TestClient().Get("/discovery")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	doc := decodeJSON[discoveryDoc](t, resp)
	// newTestAuth pins Configuration.Issuer to "https://issuer.example", so the relative
	// override resolves against that fixed issuer here too - see the sibling BaseURL-only test
	// below for proof it still tracks a genuinely dynamic per-request base URL.
	qt.Check(t, qt.Equals(doc.TokenEndpoint, "https://issuer.example/oauth2/token"))
	qt.Check(t, qt.Equals(doc.UserinfoEndpoint, "https://gateway.example/oauth2/userinfo"))
}

func TestDiscoveryRelativeEndpointOverrideTracksPerRequestBaseURL(t *testing.T) {
	app := core.New()

	conf := config.New()
	qt.Assert(t, qt.IsNil(conf.Load(nil, conf, string(app.Env()))))
	app.SetConfig(nil, conf)
	t.Cleanup(app.Stop)

	cfg := &auth.Configuration{
		Secret:                  "0123456789abcdef0123456789abcdef",
		SameSite:                "strict",
		LogoutInvalidatesCookie: true,
		// Issuer/BaseURL deliberately unset - the issuer, and so the relative override, must
		// track whatever base URL each request resolves to.
	}

	a, err := auth.New(app, cfg, stubUsers{info: auth.UserInfo{ID: "u1"}}, session.NewMemoryStore(),
		client.NewMemoryRegistry(&client.Client{ID: "spa"}))
	qt.Assert(t, qt.IsNil(err))

	h := New(a, TokenEndpoint("/oauth2/token"))

	testApp := newTestApp(t)
	testApp.Get("/discovery", h.OIDC.Discovery)

	tc := testApp.TestClient()

	resp, err := tc.Get("/discovery", tc.WithHost("one.example"))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(decodeJSON[discoveryDoc](t, resp).TokenEndpoint, "http://one.example/oauth2/token"))

	resp2, err := tc.Get("/discovery", tc.WithHost("two.example"))
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(decodeJSON[discoveryDoc](t, resp2).TokenEndpoint, "http://two.example/oauth2/token"))
}

func TestDiscoveryMountedIndividuallyStaysCorrectWithPinnedIssuer(t *testing.T) {
	// newTestAuth pins Configuration.Issuer, so a Handler built via New (not Bind) - which
	// never learns a mountPrefix - still produces a correct document, per the documented
	// workaround on Handler.mountPrefix/discovery.
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{ID: "spa"})
	h := New(a)

	app := newTestApp(t)
	app.Get("/completely/custom/path", h.OIDC.Discovery)

	resp, err := app.TestClient().Get("/completely/custom/path")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	doc := decodeJSON[discoveryDoc](t, resp)
	qt.Check(t, qt.Equals(doc.Issuer, "https://issuer.example"))
	qt.Check(t, qt.Equals(doc.TokenEndpoint, "https://issuer.example/token"))
	qt.Check(t, qt.Equals(doc.UserinfoEndpoint, "https://issuer.example/userinfo"))
}
