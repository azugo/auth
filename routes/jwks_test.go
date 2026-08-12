package routes

import (
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/client"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestJWKSNotMountedWithoutKeyProvider(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{ID: "spa"})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().Get("/auth/.well-known/jwks.json")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 404))
}

func TestJWKSReturnsPublicKeys(t *testing.T) {
	priv, pub := genRSAPEM(t)
	opts := []auth.Option{auth.KeyProvider(mustKeyProvider(t, priv, pub))}

	a := newTestAuthWithOpts(t, session.NewMemoryStore(), opts, &client.Client{ID: "spa"})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().Get("/auth/.well-known/jwks.json")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	jwks := decodeJSON[token.JWKS](t, resp)
	qt.Assert(t, qt.HasLen(jwks.Keys, 1))
	qt.Check(t, qt.Equals(jwks.Keys[0].Kid, "k1"))
	qt.Check(t, qt.Equals(jwks.Keys[0].Kty, "RSA"))
	qt.Check(t, qt.Equals(jwks.Keys[0].Alg, "RS256"))
}
