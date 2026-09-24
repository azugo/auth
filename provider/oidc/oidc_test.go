package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"

	nethttp "net/http"
)

// testIdP is a minimal OIDC server: discovery, JWKS and token endpoint.
type testIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	// claims are the id_token claims minted by the token endpoint (iss/aud/exp filled in
	// unless already set).
	claims jwt.MapClaims
	// kid is the id_token header kid; jwksKid is the one published in the JWKS.
	kid     string
	jwksKid string
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	qt.Assert(t, qt.IsNil(err))

	idp := &testIdP{key: key, kid: "k1", jwksKid: "k1", claims: jwt.MapClaims{}}

	mux := nethttp.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 idp.srv.URL,
			"authorization_endpoint": idp.srv.URL + "/authorize",
			"token_endpoint":         idp.srv.URL + "/token",
			"jwks_uri":               idp.srv.URL + "/jwks",
			"end_session_endpoint":   idp.srv.URL + "/logout",
		})
	})

	mux.HandleFunc("/jwks", func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		pub := &idp.key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": idp.jwksKid, "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}),
			}},
		})
	})

	mux.HandleFunc("/token", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_ = r.ParseForm()

		claims := jwt.MapClaims{
			"iss": idp.srv.URL, "aud": "cid", "sub": "s1",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}

		for k, v := range idp.claims {
			claims[k] = v
		}

		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		if idp.kid != "" {
			tok.Header["kid"] = idp.kid
		}

		signed, err := tok.SignedString(idp.key)
		qt.Assert(t, qt.IsNil(err))

		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-" + r.Form.Get("code"), "token_type": "Bearer",
			"expires_in": 3600, "id_token": signed,
		})
	})

	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)

	return idp
}

func newTestProvider(idp *testIdP) *Provider {
	return New(Config{
		Issuer:       idp.srv.URL,
		ClientID:     "cid",
		ClientSecret: "secret",
		RedirectURL:  "https://app.example/cb",
	})
}

func TestAuthURLCarriesPKCEAndDefaults(t *testing.T) {
	idp := newTestIdP(t)
	p := newTestProvider(idp)

	uri, err := p.AuthURL(context.Background(), "st1", "n1", "cc1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(strings.HasPrefix(uri, idp.srv.URL+"/authorize?")))

	u, err := url.Parse(uri)
	qt.Assert(t, qt.IsNil(err))

	q := u.Query()
	qt.Check(t, qt.Equals(q.Get("response_type"), "code"))
	qt.Check(t, qt.Equals(q.Get("client_id"), "cid"))
	qt.Check(t, qt.Equals(q.Get("state"), "st1"))
	qt.Check(t, qt.Equals(q.Get("nonce"), "n1"))
	qt.Check(t, qt.Equals(q.Get("code_challenge"), "cc1"))
	qt.Check(t, qt.Equals(q.Get("code_challenge_method"), "S256"))
	qt.Check(t, qt.StringContains(q.Get("scope"), "openid"))
}

func TestExchangeValidatesIDToken(t *testing.T) {
	idp := newTestIdP(t)
	idp.claims["nonce"] = "n1"
	idp.claims["email"] = "alice@example.com"

	p := newTestProvider(idp)

	tokens, err := p.Exchange(context.Background(), "c1", "verifier", "n1")
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(tokens.AccessToken, "at-c1"))
	qt.Check(t, qt.IsTrue(tokens.IDToken != ""))
	qt.Check(t, qt.Equals(tokens.RawClaims["sub"], "s1"))
	qt.Check(t, qt.Equals(tokens.RawClaims["email"], "alice@example.com"))
	qt.Check(t, qt.IsFalse(tokens.Expiry.IsZero()))
}

func TestExchangeRejectsNonceMismatch(t *testing.T) {
	idp := newTestIdP(t)
	idp.claims["nonce"] = "other"

	p := newTestProvider(idp)

	_, err := p.Exchange(context.Background(), "c1", "verifier", "n1")
	qt.Check(t, qt.ErrorMatches(err, ".*nonce mismatch.*"))
}

func TestExchangeRejectsWrongAudience(t *testing.T) {
	idp := newTestIdP(t)
	idp.claims["nonce"] = "n1"
	idp.claims["aud"] = "someone-else"

	p := newTestProvider(idp)

	_, err := p.Exchange(context.Background(), "c1", "verifier", "n1")
	qt.Check(t, qt.ErrorMatches(err, ".*audience.*"))
}

func TestExchangeRejectsWrongIssuer(t *testing.T) {
	idp := newTestIdP(t)
	idp.claims["nonce"] = "n1"
	idp.claims["iss"] = "https://evil.example"

	p := newTestProvider(idp)

	_, err := p.Exchange(context.Background(), "c1", "verifier", "n1")
	qt.Check(t, qt.ErrorMatches(err, ".*issuer.*"))
}

func TestExchangeRejectsExpiredToken(t *testing.T) {
	idp := newTestIdP(t)
	idp.claims["nonce"] = "n1"
	idp.claims["exp"] = time.Now().Add(-time.Hour).Unix()

	p := newTestProvider(idp)

	_, err := p.Exchange(context.Background(), "c1", "verifier", "n1")
	qt.Check(t, qt.ErrorMatches(err, ".*expired.*"))
}

func TestClockSkewWidensIDTokenLeeway(t *testing.T) {
	idp := newTestIdP(t)
	idp.claims["nonce"] = "n1"
	idp.claims["exp"] = time.Now().Add(-2 * time.Minute).Unix()

	// An unset ClockSkew validates strictly.
	_, err := newTestProvider(idp).Exchange(context.Background(), "c1", "verifier", "n1")
	qt.Check(t, qt.ErrorMatches(err, ".*expired.*"))

	p := New(Config{
		Issuer: idp.srv.URL, ClientID: "cid", ClientSecret: "secret",
		RedirectURL: "https://app.example/cb", ClockSkew: 5 * time.Minute,
	})

	_, err = p.Exchange(context.Background(), "c1", "verifier", "n1")
	qt.Check(t, qt.IsNil(err))
}

func TestExchangeAcceptsTokenWithoutKid(t *testing.T) {
	idp := newTestIdP(t)
	idp.claims["nonce"] = "n1"
	// The JWKS labels its single key, but the id_token header omits kid (OIDC Core section 10.1).
	idp.kid = ""

	p := newTestProvider(idp)

	_, err := p.Exchange(context.Background(), "c1", "verifier", "n1")
	qt.Check(t, qt.IsNil(err))
}

func TestExchangeRejectsUnknownKid(t *testing.T) {
	idp := newTestIdP(t)
	idp.claims["nonce"] = "n1"
	// The token header names a kid the published JWKS does not contain.
	idp.kid = "k2"

	p := newTestProvider(idp)

	_, err := p.Exchange(context.Background(), "c1", "verifier", "n1")
	qt.Check(t, qt.ErrorMatches(err, ".*no key for kid.*"))
}

func TestIssuerCheckOverride(t *testing.T) {
	idp := newTestIdP(t)
	idp.claims["nonce"] = "n1"
	idp.claims["iss"] = "https://tenant.example/v2.0"

	p := New(Config{
		Issuer: idp.srv.URL, ClientID: "cid", RedirectURL: "https://app.example/cb",
		IssuerCheck: func(iss string) error {
			qt.Check(t, qt.Equals(iss, "https://tenant.example/v2.0"))

			return nil
		},
	})

	_, err := p.Exchange(context.Background(), "c1", "verifier", "n1")
	qt.Check(t, qt.IsNil(err))
}

func TestLogoutURL(t *testing.T) {
	idp := newTestIdP(t)
	p := &LogoutProvider{Provider: newTestProvider(idp)}

	uri, err := p.LogoutURL(context.Background(), "idt", "st1", "https://app.example/auth/external/x/logout/callback")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(strings.HasPrefix(uri, idp.srv.URL+"/logout?")))

	u, err := url.Parse(uri)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(u.Query().Get("id_token_hint"), "idt"))
	qt.Check(t, qt.Equals(u.Query().Get("state"), "st1"))
	qt.Check(t, qt.Equals(u.Query().Get("post_logout_redirect_uri"), "https://app.example/auth/external/x/logout/callback"))
}

func TestDefaultClientBoundsSlowIdP(t *testing.T) {
	blocked := make(chan struct{})

	srv := httptest.NewServer(nethttp.HandlerFunc(func(nethttp.ResponseWriter, *nethttp.Request) {
		<-blocked
	}))

	// Close runs last and waits for the handler, so the handler is released first.
	defer srv.Close()
	defer close(blocked)

	p := New(Config{Issuer: srv.URL, ClientID: "cid", RedirectURL: "https://app.example/cb"})

	// A context deadline bounds the call even though the handler never responds.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := p.AuthURL(ctx, "state", "nonce", "challenge")

	qt.Check(t, qt.IsNotNil(err))
	qt.Check(t, qt.IsTrue(time.Since(start) < 5*time.Second), qt.Commentf("took %s", time.Since(start)))
}

func TestDiscoveryFetchDoesNotHoldTheLock(t *testing.T) {
	idp := newTestIdP(t)
	p := newTestProvider(idp)

	// Concurrent first uses must not serialize behind one another's network call.
	var wg sync.WaitGroup

	wg.Add(8)

	for range 8 {
		go func() {
			defer wg.Done()

			_, err := p.AuthURL(context.Background(), "state", "nonce", "challenge")
			qt.Check(t, qt.IsNil(err))
		}()
	}

	wg.Wait()
}
