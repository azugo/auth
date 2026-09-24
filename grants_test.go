package auth

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/code"
	"azugo.io/auth/contract"
	"azugo.io/auth/event"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/core/password"
	"azugo.io/core/test"
	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
)

// newGrantsTestAuth builds an Auth with the standard fake users and any number of clients.
func newGrantsTestAuth(t *testing.T, cfg *Configuration, opts []Option, cls ...*client.Client) *Auth {
	t.Helper()

	users := fakeUsers{
		users: map[string]UserInfo{
			"alice": {ID: "u1", Name: "Alice", Email: "alice@example.com", Scope: "openid profile"},
		},
		passwords: map[string]string{"alice": "secret123"},
	}

	if cfg == nil {
		cfg = validConfig()
	}

	cfg.LogoutInvalidatesCookie = true

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(cls...), opts...)
	qt.Assert(t, qt.IsNil(err))

	return a
}

// portalClient is the password-grant client used to establish the session cookie.
func portalClient() *client.Client {
	return &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	}
}

// codeClient is a public authorization-code client with PKCE.
func codeClient() *client.Client {
	return &client.Client{
		ID: "web", GrantTypes: []string{"authorization_code"},
		RedirectURIs: []string{"https://web.example/callback"},
		Public:       true, RequirePKCE: true,
		ResponseMode: client.ResponseModeJSON,
	}
}

// login establishes alice's session and returns the session cookie token.
func login(t *testing.T, a *Auth) string {
	t.Helper()

	res, err := a.Login(context.Background(), LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", BaseURL: "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))

	return res.Cookie.Value
}

// pkce is a fixed RFC 7636 verifier/S256 challenge pair.
const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// authorizeCode runs the full happy-path GET /authorize and returns the minted code.
func authorizeCode(t *testing.T, a *Auth, sessionToken, scope, nonce string) string {
	t.Helper()

	res, err := a.Authorize(context.Background(), AuthorizeRequest{
		ResponseType: "code", ClientID: "web",
		RedirectURI: "https://web.example/callback",
		Scope:       scope, State: "xyz", Nonce: nonce,
		CodeChallenge: pkceChallenge, CodeChallengeMethod: "S256",
		SessionToken: sessionToken,
	})
	qt.Assert(t, qt.IsNil(err))

	u, err := url.Parse(res.Redirect)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(u.Query().Get("state"), "xyz"))
	qt.Assert(t, qt.IsTrue(u.Query().Get("code") != ""))

	// The eventually-consistent memory cache needs a beat before the code is redeemable.

	return u.Query().Get("code")
}

func TestAuthorizationCodeFlowEndToEnd(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)

	cfg := validConfig()
	cfg.Keys = keySetConfig(priv, pub)

	a := newGrantsTestAuth(t, cfg, nil, portalClient(), codeClient())
	cookie := login(t, a)

	codeVal := authorizeCode(t, a, cookie, "openid profile", "n0nce")

	res, err := a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
		Credentials:  ClientCredentials{ClientID: "web"},
		Code:         codeVal,
		RedirectURI:  "https://web.example/callback",
		CodeVerifier: pkceVerifier,
		BaseURL:      "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(res.AccessToken != ""))
	qt.Check(t, qt.Equals(res.TokenType, "Bearer"))
	qt.Check(t, qt.Equals(res.Scope, "openid profile"))
	qt.Assert(t, qt.IsTrue(res.IDToken != ""))

	// The id_token echoes the nonce and carries auth_time.
	claims := decodeIDToken(t, res.IDToken, pub)
	qt.Check(t, qt.Equals(claims["nonce"], "n0nce"))
	qt.Check(t, qt.Equals(claims["aud"], "web"))
	qt.Check(t, qt.IsTrue(claims["auth_time"] != nil))

	info, _, err := a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.ID, "u1"))
}

func keySetConfig(priv, pub string) *contract.KeySetConfig {
	return &contract.KeySetConfig{
		Primary: contract.KeyConfig{ID: "k1", Algorithm: "RS256", PrivateKey: priv, PublicKey: pub},
	}
}

func decodeIDToken(t *testing.T, idToken, pubPEM string) jwt.MapClaims {
	t.Helper()

	pub, err := token.ParsePublicKeyPEM(pubPEM)
	qt.Assert(t, qt.IsNil(err))

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(idToken, claims, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"RS256"}))
	qt.Assert(t, qt.IsNil(err))

	return claims
}

func TestAuthorizeRejectsUnregisteredRedirectURI(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient())
	cookie := login(t, a)

	_, err := a.Authorize(context.Background(), AuthorizeRequest{
		ResponseType: "code", ClientID: "web",
		RedirectURI:  "https://evil.example/callback",
		SessionToken: cookie,
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

func TestAuthorizeErrorsRedirectAfterURIValidation(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient())
	cookie := login(t, a)

	res, err := a.Authorize(context.Background(), AuthorizeRequest{
		ResponseType: "token", ClientID: "web",
		RedirectURI:  "https://web.example/callback",
		State:        "xyz",
		SessionToken: cookie,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(res.Redirect, "error=unsupported_response_type"))
	qt.Check(t, qt.StringContains(res.Redirect, "state=xyz"))
}

func TestAuthorizeRequiresPKCEForPublicClient(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient())
	cookie := login(t, a)

	res, err := a.Authorize(context.Background(), AuthorizeRequest{
		ResponseType: "code", ClientID: "web",
		RedirectURI:  "https://web.example/callback",
		SessionToken: cookie,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(res.Redirect, "error=invalid_request"))
	qt.Check(t, qt.StringContains(res.Redirect, "code_challenge"))
}

func TestAuthorizeRejectsMalformedCodeChallenge(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient())
	cookie := login(t, a)

	res, err := a.Authorize(context.Background(), AuthorizeRequest{
		ResponseType: "code", ClientID: "web",
		RedirectURI:   "https://web.example/callback",
		CodeChallenge: "too-short", CodeChallengeMethod: "S256",
		SessionToken: cookie,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(res.Redirect, "error=invalid_request"))
}

func TestAuthorizationCodeGrantRejectsMalformedVerifier(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient())
	cookie := login(t, a)
	codeVal := authorizeCode(t, a, cookie, "profile", "")

	// Correct length and charset are required before the S256 comparison; "!" is outside the
	// RFC 7636 unreserved set.
	_, err := a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
		Credentials:  ClientCredentials{ClientID: "web"},
		Code:         codeVal,
		RedirectURI:  "https://web.example/callback",
		CodeVerifier: strings.Repeat("!", 43),
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
}

func TestAuthorizeRejectsPlainPKCEMethod(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient())
	cookie := login(t, a)

	res, err := a.Authorize(context.Background(), AuthorizeRequest{
		ResponseType: "code", ClientID: "web",
		RedirectURI:   "https://web.example/callback",
		CodeChallenge: pkceChallenge, CodeChallengeMethod: "plain",
		SessionToken: cookie,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(res.Redirect, "error=invalid_request"))
}

func TestAuthorizeRequiresLogin(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient())

	_, err := a.Authorize(context.Background(), AuthorizeRequest{
		ResponseType: "code", ClientID: "web",
		RedirectURI:   "https://web.example/callback",
		CodeChallenge: pkceChallenge, CodeChallengeMethod: "S256",
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeLoginRequired))
}

func TestAuthorizeRejectsScopeBeyondSession(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient())
	cookie := login(t, a)

	res, err := a.Authorize(context.Background(), AuthorizeRequest{
		ResponseType: "code", ClientID: "web",
		RedirectURI:   "https://web.example/callback",
		Scope:         "openid admin",
		CodeChallenge: pkceChallenge, CodeChallengeMethod: "S256",
		SessionToken: cookie,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(res.Redirect, "error=invalid_scope"))
}

func TestAuthorizationCodeReplayRevokesIssuedTokenOnly(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient())
	cookie := login(t, a)
	codeVal := authorizeCode(t, a, cookie, "profile", "")

	redeem := func() (TokenResult, error) {
		return a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
			Credentials:  ClientCredentials{ClientID: "web"},
			Code:         codeVal,
			RedirectURI:  "https://web.example/callback",
			CodeVerifier: pkceVerifier,
		})
	}

	res, err := redeem()
	qt.Assert(t, qt.IsNil(err))

	_, err = redeem()
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	// The token issued from the replayed code is dead...
	_, _, err = a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Check(t, qt.IsNotNil(err))

	// ...but the user's session, shared with every other client, survives.
	_, err = a.Refresh(context.Background(), RefreshRequest{Token: cookie})
	qt.Check(t, qt.IsNil(err))
}

func TestAuthorizationCodeReplayByForeignClientRevokesNothing(t *testing.T) {
	other := codeClient()
	other.ID = "other"

	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient(), other)
	cookie := login(t, a)
	codeVal := authorizeCode(t, a, cookie, "profile", "")

	res, err := a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
		Credentials:  ClientCredentials{ClientID: "web"},
		Code:         codeVal,
		RedirectURI:  "https://web.example/callback",
		CodeVerifier: pkceVerifier,
	})
	qt.Assert(t, qt.IsNil(err))

	// Anyone who learns the code can replay it under their own identity; that must not let
	// them revoke the token, or the session, of the client the code belonged to.
	_, err = a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
		Credentials:  ClientCredentials{ClientID: "other"},
		Code:         codeVal,
		RedirectURI:  "https://web.example/callback",
		CodeVerifier: pkceVerifier,
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	_, _, err = a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Check(t, qt.IsNil(err))

	_, err = a.Refresh(context.Background(), RefreshRequest{Token: cookie})
	qt.Check(t, qt.IsNil(err))
}

// nilReplayStore violates the Store contract by returning ErrReplayed without the record.
type nilReplayStore struct{}

func (nilReplayStore) Save(context.Context, *code.AuthorizationCode) error { return nil }

func (nilReplayStore) Consume(context.Context, string) (*code.AuthorizationCode, error) {
	return nil, code.ErrReplayed
}

func (nilReplayStore) BindIssuedToken(context.Context, string, string, time.Time) error {
	return nil
}

func TestAuthorizationCodeReplayWithNilRecordDoesNotPanic(t *testing.T) {
	a := newGrantsTestAuth(t, nil, []Option{CodeStore(nilReplayStore{})}, portalClient(), codeClient())

	_, err := a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
		Credentials: ClientCredentials{ClientID: "web"},
		Code:        "any",
		RedirectURI: "https://web.example/callback",
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
}

func TestAuthorizationCodeReplayDenyListsIssuedJWT(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)
	cfg := validConfig()
	cfg.Keys = keySetConfig(priv, pub)

	cl := codeClient()
	cl.AccessTokenType = client.AccessTokenTypeJWT

	a := newGrantsTestAuth(t, cfg, nil, portalClient(), cl)
	cookie := login(t, a)
	codeVal := authorizeCode(t, a, cookie, "profile", "")

	redeem := func() (TokenResult, error) {
		return a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
			Credentials:  ClientCredentials{ClientID: "web"},
			Code:         codeVal,
			RedirectURI:  "https://web.example/callback",
			CodeVerifier: pkceVerifier,
		})
	}

	res, err := redeem()
	qt.Assert(t, qt.IsNil(err))

	info, err := a.ValidateJWTAccessToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.ID, "u1"))

	_, err = redeem()
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	// The JWT issued at the first redemption is deny-listed by the replay.
	_, err = a.ValidateJWTAccessToken(context.Background(), res.AccessToken)
	qt.Check(t, qt.IsNotNil(err))
}

func TestJWTAccessTokenIdentityCarriesGrantedScope(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)
	cfg := validConfig()
	cfg.Keys = keySetConfig(priv, pub)

	cl := codeClient()
	cl.AccessTokenType = client.AccessTokenTypeJWT

	a := newGrantsTestAuth(t, cfg, nil, portalClient(), cl)
	cookie := login(t, a)
	codeVal := authorizeCode(t, a, cookie, "profile", "")

	res, err := a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
		Credentials:  ClientCredentials{ClientID: "web"},
		Code:         codeVal,
		RedirectURI:  "https://web.example/callback",
		CodeVerifier: pkceVerifier,
	})
	qt.Assert(t, qt.IsNil(err))

	// Alice's maximal scope is "openid profile"; the token was granted only "profile".
	info, err := a.ValidateJWTAccessToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Scope, "profile"))
}

func TestOpaqueCodeGrantTokenBindsScopeAndClient(t *testing.T) {
	rs := serviceClient(t, "s3cret")

	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient(), rs)
	cookie := login(t, a)
	codeVal := authorizeCode(t, a, cookie, "profile", "")

	res, err := a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
		Credentials:  ClientCredentials{ClientID: "web"},
		Code:         codeVal,
		RedirectURI:  "https://web.example/callback",
		CodeVerifier: pkceVerifier,
	})
	qt.Assert(t, qt.IsNil(err))

	// Introspection reports the token's granted scope and issuing client, not the portal
	// session's.
	out, err := a.Introspect(context.Background(), IntrospectRequest{
		Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"},
		Token:       res.AccessToken,
		BaseURL:     "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(out.Active))
	qt.Check(t, qt.Equals(out.Scope, "profile"))
	qt.Check(t, qt.Equals(out.ClientID, "web"))
	qt.Check(t, qt.Equals(out.Audience, "web"))

	// The local middleware identity is narrowed the same way.
	info, _, err := a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Scope, "profile"))

	// The issuing client can revoke its own token.
	err = a.RevokeToken(context.Background(), RevokeTokenRequest{
		Credentials: ClientCredentials{ClientID: "web"},
		Token:       res.AccessToken,
	})
	qt.Assert(t, qt.IsNil(err))

	out, err = a.Introspect(context.Background(), IntrospectRequest{
		Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"},
		Token:       res.AccessToken,
		BaseURL:     "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(out.Active))
}

func TestAuthorizeRejectsScopeBeyondClientRegistration(t *testing.T) {
	cl := codeClient()
	cl.Scopes = []string{"openid"}

	a := newGrantsTestAuth(t, nil, nil, portalClient(), cl)
	cookie := login(t, a)

	// "profile" is in the session scope but not in the client's registered Scopes.
	res, err := a.Authorize(context.Background(), AuthorizeRequest{
		ResponseType: "code", ClientID: "web",
		RedirectURI:   "https://web.example/callback",
		Scope:         "profile",
		CodeChallenge: pkceChallenge, CodeChallengeMethod: "S256",
		SessionToken: cookie,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(res.Redirect, "error=invalid_scope"))
}

func TestAuthorizeDefaultScopeNarrowedToClientRegistration(t *testing.T) {
	cl := codeClient()
	cl.Scopes = []string{"profile"}

	a := newGrantsTestAuth(t, nil, nil, portalClient(), cl)
	cookie := login(t, a)
	codeVal := authorizeCode(t, a, cookie, "", "")

	res, err := a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
		Credentials:  ClientCredentials{ClientID: "web"},
		Code:         codeVal,
		RedirectURI:  "https://web.example/callback",
		CodeVerifier: pkceVerifier,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Scope, "profile"))
}

func TestAuthorizationCodeGrantRejectsBadVerifier(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient())
	cookie := login(t, a)
	codeVal := authorizeCode(t, a, cookie, "profile", "")

	_, err := a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
		Credentials:  ClientCredentials{ClientID: "web"},
		Code:         codeVal,
		RedirectURI:  "https://web.example/callback",
		CodeVerifier: "wrong-verifier-wrong-verifier-wrong-verifier",
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
}

func TestAuthorizationCodeGrantRejectsForeignClient(t *testing.T) {
	other := &client.Client{
		ID: "other", GrantTypes: []string{"authorization_code"},
		RedirectURIs: []string{"https://web.example/callback"},
	}

	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient(), other)
	cookie := login(t, a)
	codeVal := authorizeCode(t, a, cookie, "profile", "")

	_, err := a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
		Credentials:  ClientCredentials{ClientID: "other"},
		Code:         codeVal,
		RedirectURI:  "https://web.example/callback",
		CodeVerifier: pkceVerifier,
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
}

func TestAuthorizationCodeGrantRejectsRedirectURIMismatch(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient())
	cookie := login(t, a)
	codeVal := authorizeCode(t, a, cookie, "profile", "")

	_, err := a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
		Credentials:  ClientCredentials{ClientID: "web"},
		Code:         codeVal,
		RedirectURI:  "https://web.example/other",
		CodeVerifier: pkceVerifier,
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
}

// serviceClient builds a confidential client_credentials client with the given secret.
func serviceClient(t *testing.T, secret string) *client.Client {
	t.Helper()

	hash, err := password.Hash(secret)
	qt.Assert(t, qt.IsNil(err))

	return &client.Client{
		ID: "svc", GrantTypes: []string{"client_credentials"},
		Scopes:                  []string{"items:read", "items:write"},
		SecretHash:              hash,
		AccessTokenType:         client.AccessTokenTypeJWT,
		TokenEndpointAuthMethod: client.TokenEndpointAuthClientSecret,
	}
}

func TestClientCredentialsGrantIssuesJWT(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)
	cfg := validConfig()
	cfg.Keys = keySetConfig(priv, pub)

	a := newGrantsTestAuth(t, cfg, nil, serviceClient(t, "s3cret"))

	res, err := a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{
		Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"},
		Scope:       "items:read",
		BaseURL:     "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Scope, "items:read"))

	set, err := a.Keys().KeySet(context.Background())
	qt.Assert(t, qt.IsNil(err))

	claims, err := token.VerifyAccessToken(set, res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(claims.Subject, "svc"))
	qt.Check(t, qt.Equals(claims.ClientID, "svc"))
	qt.Check(t, qt.Equals(claims.Scope, "items:read"))
	qt.Check(t, qt.Equals(claims.Issuer, "https://issuer.example"))
	qt.Check(t, qt.IsTrue(claims.TokenID != ""))
}

func TestClientCredentialsGrantRejectsWrongSecret(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)
	cfg := validConfig()
	cfg.Keys = keySetConfig(priv, pub)

	a := newGrantsTestAuth(t, cfg, nil, serviceClient(t, "s3cret"))

	_, err := a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{
		Credentials: ClientCredentials{ClientID: "svc", Secret: "wrong"},
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidClient))
}

func TestClientCredentialsGrantRejectsPublicClient(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, &client.Client{
		ID: "pub", GrantTypes: []string{"client_credentials"}, Public: true,
	})

	_, err := a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{
		Credentials: ClientCredentials{ClientID: "pub"},
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnauthorizedClient))
}

func TestClientCredentialsGrantRejectsScopeBeyondRegistered(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)
	cfg := validConfig()
	cfg.Keys = keySetConfig(priv, pub)

	a := newGrantsTestAuth(t, cfg, nil, serviceClient(t, "s3cret"))

	_, err := a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{
		Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"},
		Scope:       "admin",
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidScope))
}

// signAssertion mints a private_key_jwt client_assertion.
func signAssertion(t *testing.T, privPEM, clientID, jti string, aud []string, exp time.Time) string {
	t.Helper()

	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privPEM))
	qt.Assert(t, qt.IsNil(err))

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": clientID, "sub": clientID, "aud": aud,
		"jti": jti, "exp": exp.Unix(), "iat": time.Now().Unix(),
	})

	signed, err := tok.SignedString(key)
	qt.Assert(t, qt.IsNil(err))

	return signed
}

func TestPrivateKeyJWTClientAuthentication(t *testing.T) {
	keysPriv, keysPub := genTestRSAKeyPair(t)
	clientPriv, clientPub := genTestRSAKeyPair(t)

	cfg := validConfig()
	cfg.Keys = keySetConfig(keysPriv, keysPub)

	cl := &client.Client{
		ID: "svc", GrantTypes: []string{"client_credentials"},
		Scopes:                  []string{"items:read"},
		PublicKey:               clientPub,
		AccessTokenType:         client.AccessTokenTypeJWT,
		TokenEndpointAuthMethod: client.TokenEndpointAuthPrivateKeyJWT,
	}

	a := newGrantsTestAuth(t, cfg, nil, cl)

	// The acceptable audiences are derived from the configured issuer: the issuer itself and
	// its token endpoint URL.
	assertion := signAssertion(t, clientPriv, "svc", "a1", []string{"https://issuer.example"}, time.Now().Add(time.Minute))
	creds := ClientCredentials{
		ClientID:      "svc",
		AssertionType: AssertionTypeJWTBearer,
		Assertion:     assertion,
	}

	_, err := a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{Credentials: creds})
	qt.Assert(t, qt.IsNil(err))

	// Replaying the same assertion (same jti) is rejected.
	_, err = a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{Credentials: creds})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidClient))

	// A wrong audience is rejected.
	badAud := creds
	badAud.Assertion = signAssertion(t, clientPriv, "svc", "a2", []string{"https://other.example"}, time.Now().Add(time.Minute))

	_, err = a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{Credentials: badAud})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidClient))

	// A secret must not be accepted for a private_key_jwt client.
	_, err = a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{
		Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"},
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidClient))
}

func TestPrivateKeyJWTRejectsTokenEndpointAudience(t *testing.T) {
	keysPriv, keysPub := genTestRSAKeyPair(t)
	clientPriv, clientPub := genTestRSAKeyPair(t)

	cfg := validConfig()
	cfg.Keys = keySetConfig(keysPriv, keysPub)

	cl := &client.Client{
		ID: "svc", GrantTypes: []string{"client_credentials"},
		Scopes:                  []string{"items:read"},
		PublicKey:               clientPub,
		AccessTokenType:         client.AccessTokenTypeJWT,
		TokenEndpointAuthMethod: client.TokenEndpointAuthPrivateKeyJWT,
	}

	a := newGrantsTestAuth(t, cfg, nil, cl)

	// Only the issuer identifier is a valid audience; the token endpoint URL is not.
	assertion := signAssertion(t, clientPriv, "svc", "a3", []string{"https://issuer.example/token"}, time.Now().Add(time.Minute))

	_, err := a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{
		Credentials: ClientCredentials{
			ClientID:      "svc",
			AssertionType: AssertionTypeJWTBearer,
			Assertion:     assertion,
		},
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidClient))
}

func TestPrivateKeyJWTAssertionLifetimeChecks(t *testing.T) {
	keysPriv, keysPub := genTestRSAKeyPair(t)
	clientPriv, clientPub := genTestRSAKeyPair(t)

	cfg := validConfig()
	cfg.Keys = keySetConfig(keysPriv, keysPub)

	cl := &client.Client{
		ID: "svc", GrantTypes: []string{"client_credentials"},
		Scopes:                  []string{"items:read"},
		PublicKey:               clientPub,
		AccessTokenType:         client.AccessTokenTypeJWT,
		TokenEndpointAuthMethod: client.TokenEndpointAuthPrivateKeyJWT,
	}

	a := newGrantsTestAuth(t, cfg, nil, cl)

	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(clientPriv))
	qt.Assert(t, qt.IsNil(err))

	grant := func(claims jwt.MapClaims) error {
		signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
		qt.Assert(t, qt.IsNil(err))

		_, err = a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{
			Credentials: ClientCredentials{
				ClientID: "svc", AssertionType: AssertionTypeJWTBearer, Assertion: signed,
			},
		})

		return err
	}

	// Missing iat is rejected.
	err = grant(jwt.MapClaims{
		"iss": "svc", "sub": "svc", "aud": "https://issuer.example",
		"jti": "l1", "exp": time.Now().Add(time.Minute).Unix(),
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidClient))

	// A lifetime beyond the cap is rejected.
	err = grant(jwt.MapClaims{
		"iss": "svc", "sub": "svc", "aud": "https://issuer.example",
		"jti": "l2", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidClient))

	// A conforming assertion still authenticates.
	err = grant(jwt.MapClaims{
		"iss": "svc", "sub": "svc", "aud": "https://issuer.example",
		"jti": "l3", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
	})
	qt.Check(t, qt.IsNil(err))
}

func TestRevokeOpaqueAccessTokenSparesTheSession(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient())

	res, err := a.Login(context.Background(), LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", BaseURL: "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))

	err = a.RevokeToken(context.Background(), RevokeTokenRequest{
		Credentials: ClientCredentials{ClientID: "spa"},
		Token:       res.AccessToken,
	})
	qt.Assert(t, qt.IsNil(err))

	_, _, err = a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Check(t, qt.IsNotNil(err))

	// The session cookie is a separate credential and keeps working.
	_, _, err = a.IntrospectToken(context.Background(), res.Cookie.Value)
	qt.Check(t, qt.IsNil(err))
}

func TestRevokeSessionCookieEndsTheSession(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient())

	res, err := a.Login(context.Background(), LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", BaseURL: "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))

	err = a.RevokeToken(context.Background(), RevokeTokenRequest{
		Credentials: ClientCredentials{ClientID: "spa"},
		Token:       res.Cookie.Value,
	})
	qt.Assert(t, qt.IsNil(err))

	_, _, err = a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Check(t, qt.IsNotNil(err))
}

func TestRevokeStaleTokenIsSilent(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient())

	res, err := a.Login(context.Background(), LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", BaseURL: "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))

	// Rotating the cookie retires the presented one; replaying that stale value from a log
	// must not end the live session.
	rotated, err := a.Refresh(context.Background(), RefreshRequest{Token: res.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))

	err = a.RevokeToken(context.Background(), RevokeTokenRequest{
		Credentials: ClientCredentials{ClientID: "spa"},
		Token:       res.Cookie.Value,
	})
	qt.Assert(t, qt.IsNil(err))

	_, _, err = a.IntrospectToken(context.Background(), rotated.Cookie.Value)
	qt.Check(t, qt.IsNil(err))
}

func TestRevokeUnknownTokenIsSilent(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient())

	err := a.RevokeToken(context.Background(), RevokeTokenRequest{
		Credentials: ClientCredentials{ClientID: "spa"},
		Token:       "garbage",
	})
	qt.Check(t, qt.IsNil(err))
}

func TestRevokeJWTDenyListsIntrospection(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)
	cfg := validConfig()
	cfg.Keys = keySetConfig(priv, pub)

	rs := serviceClient(t, "s3cret")
	a := newGrantsTestAuth(t, cfg, nil, rs)

	res, err := a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{
		Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"},
		BaseURL:     "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))

	introspect := func() IntrospectionResponse {
		out, err := a.Introspect(context.Background(), IntrospectRequest{
			Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"},
			Token:       res.AccessToken,
			BaseURL:     "https://issuer.example",
		})
		qt.Assert(t, qt.IsNil(err))

		return out
	}

	active := introspect()
	qt.Check(t, qt.IsTrue(active.Active))
	qt.Check(t, qt.Equals(active.ClientID, "svc"))
	qt.Check(t, qt.Equals(active.Subject, "svc"))

	err = a.RevokeToken(context.Background(), RevokeTokenRequest{
		Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"},
		Token:       res.AccessToken,
	})
	qt.Assert(t, qt.IsNil(err))

	revoked := introspect()
	qt.Check(t, qt.IsFalse(revoked.Active))
	qt.Check(t, qt.Equals(revoked.ClientID, ""))
}

func TestIntrospectActiveOpaqueToken(t *testing.T) {
	rs := serviceClient(t, "s3cret")
	a := newGrantsTestAuth(t, nil, nil, portalClient(), rs)

	res, err := a.Login(context.Background(), LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", BaseURL: "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))

	out, err := a.Introspect(context.Background(), IntrospectRequest{
		Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"},
		Token:       res.AccessToken,
		BaseURL:     "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(out.Active))
	qt.Check(t, qt.Equals(out.Subject, "u1"))
	qt.Check(t, qt.Equals(out.ClientID, "spa"))
	qt.Check(t, qt.Equals(out.Username, "Alice"))
	qt.Check(t, qt.Equals(out.Issuer, "https://issuer.example"))
	qt.Check(t, qt.IsTrue(out.ExpiresAt > time.Now().Unix()))
	qt.Check(t, qt.IsTrue(out.SessionID != ""))
}

func TestIntrospectInactiveIsBare(t *testing.T) {
	rs := serviceClient(t, "s3cret")
	a := newGrantsTestAuth(t, nil, nil, rs)

	out, err := a.Introspect(context.Background(), IntrospectRequest{
		Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"},
		Token:       "v4.local.garbage",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(out, IntrospectionResponse{}))
}

func TestIntrospectRejectsPublicClient(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient())

	_, err := a.Introspect(context.Background(), IntrospectRequest{
		Credentials: ClientCredentials{ClientID: "spa"},
		Token:       "whatever",
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidClient))
}

func TestLoginThrottleLocksOutAfterMaxAttempts(t *testing.T) {
	cfg := validConfig()
	cfg.LogoutInvalidatesCookie = true
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a := newGrantsTestAuth(t, cfg, nil, portalClient())

	fail := func() error {
		_, err := a.Login(context.Background(), LoginRequest{
			Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "wrong", IP: "203.0.113.9",
		})

		return err
	}

	qt.Check(t, qt.Equals(oauthErrorCode(t, fail()), ErrCodeInvalidGrant))
	qt.Check(t, qt.Equals(oauthErrorCode(t, fail()), ErrCodeInvalidGrant))

	// Third attempt is locked out even with the correct password.
	_, err := a.Login(context.Background(), LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", IP: "203.0.113.9",
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))
}

func TestLoginEmitsAuditEvents(t *testing.T) {
	var got []event.Event

	sink := event.SinkFunc(func(_ context.Context, e event.Event) {
		got = append(got, e)
	})

	a := newGrantsTestAuth(t, nil, []Option{Events(sink)}, portalClient())

	_, _ = a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "wrong"})
	_, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.HasLen(got, 2))
	qt.Check(t, qt.Equals(got[0].Type, event.TypeLoginFailure))
	qt.Check(t, qt.Equals(got[0].Detail["username"], "alice"))
	qt.Check(t, qt.Equals(got[1].Type, event.TypeLoginSuccess))
	qt.Check(t, qt.Equals(got[1].UserID, "u1"))
	qt.Check(t, qt.Equals(got[1].Detail["username"], "alice"))
}

func TestMultiWriteSequencesRunInsideTransactor(t *testing.T) {
	var calls int

	tx := TransactorFunc(func(ctx context.Context, fn func(ctx context.Context) error) error {
		calls++

		return fn(ctx)
	})

	a := newGrantsTestAuth(t, nil, []Option{Transactor(tx)}, portalClient())

	res, err := a.Login(context.Background(), LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123",
	})
	qt.Assert(t, qt.IsNil(err))
	// Login wraps session create + cookie JTI issue.
	qt.Check(t, qt.Equals(calls, 1))

	_, err = a.Logout(context.Background(), LogoutRequest{Token: res.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))
	// Logout wraps session revoke + JTI revoke.
	qt.Check(t, qt.Equals(calls, 2))
}

func TestDefaultEventSinkLogsViaAppLogger(t *testing.T) {
	app := newApp(t)
	observed := test.ObservedLogs(app)

	cfg := validConfig()
	cfg.LogoutInvalidatesCookie = true

	users := fakeUsers{
		users:     map[string]UserInfo{"alice": {ID: "u1", Name: "Alice", Scope: "profile"}},
		passwords: map[string]string{"alice": "secret123"},
	}

	a, err := New(app, cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(portalClient()))
	qt.Assert(t, qt.IsNil(err))

	_, err = a.Login(context.Background(), LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", IP: "203.0.113.9",
	})
	qt.Assert(t, qt.IsNil(err))

	entries := observed.FilterMessage("auth event").All()
	qt.Assert(t, qt.HasLen(entries, 1))
	qt.Check(t, qt.Equals(entries[0].LoggerName, "auth.event"))

	fields := entries[0].ContextMap()
	qt.Check(t, qt.Equals(fields["event.action"], event.TypeLoginSuccess))
	qt.Check(t, qt.Equals(fields["user.id"], "u1"))
	qt.Check(t, qt.Equals(fields["client.id"], "spa"))
	// Emitted with a plain context - the sink includes source.ip itself; inside a request it
	// is left to the request logger.
	qt.Check(t, qt.Equals(fields["source.ip"], "203.0.113.9"))
	qt.Check(t, qt.Equals(fields["user.name"], "alice"))
}

func TestLoginRedirectSanitizesReturnTo(t *testing.T) {
	ssr := &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeRedirect,
	}

	a := newGrantsTestAuth(t, nil, nil, ssr)

	for in, want := range map[string]string{
		"/dashboard":            "/dashboard",
		"/dashboard?tab=2":      "/dashboard?tab=2",
		"":                      "/",
		"https://evil.example":  "/",
		"//evil.example":        "/",
		"/\\evil.example":       "/",
		"/\t\\evil.example":     "/",
		"////evil.example":      "/",
		"/%2F%2Fevil.example":   "/",
		"javascript:alert(1)":   "/",
		"/a\\b":                 "/a%5Cb",
		"/ok\t":                 "/",
		"https:/evil.example":   "/",
		"\\/\\/evil.example":    "/",
		"/dashboard#/deep/link": "/dashboard",
	} {
		res, err := a.Login(context.Background(), LoginRequest{
			Credentials: ClientCredentials{ClientID: "ssr"}, Username: "alice", Password: "secret123", ReturnTo: in,
		})
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(res.ReturnTo, want), qt.Commentf("returnTo %q", in))
	}
}

func TestJWTAccessTokenValidatedByMiddlewarePath(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)
	cfg := validConfig()
	cfg.Keys = keySetConfig(priv, pub)

	// A JWT-type portal client: password login issues a signed JWT access token.
	cl := portalClient()
	cl.AccessTokenType = client.AccessTokenTypeJWT

	a := newGrantsTestAuth(t, cfg, nil, cl)

	res, err := a.Login(context.Background(), LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", BaseURL: "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(strings.Count(res.AccessToken, ".") == 2))

	info, err := a.ValidateJWTAccessToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.ID, "u1"))
}

func TestThirdPartyAccessTokenIsNotASessionCredential(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient())
	cookie := login(t, a)

	res, err := a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
		Credentials: ClientCredentials{ClientID: "web"}, Code: authorizeCode(t, a, cookie, "openid", ""),
		RedirectURI: "https://web.example/callback", CodeVerifier: pkceVerifier,
	})
	qt.Assert(t, qt.IsNil(err))

	// The token introspects with its own scope...
	info, _, err := a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Scope, "openid"))

	// ...but is refused wherever the session cookie or a first-party credential is expected.
	_, err = a.Refresh(context.Background(), RefreshRequest{Token: res.AccessToken})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeLoginRequired))

	_, err = a.Authorize(context.Background(), AuthorizeRequest{
		ResponseType: "code", ClientID: "web", RedirectURI: "https://web.example/callback",
		CodeChallenge: pkceChallenge, CodeChallengeMethod: "S256", SessionToken: res.AccessToken,
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeLoginRequired))

	_, _, err = a.IntrospectFirstParty(context.Background(), res.AccessToken)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientScope))

	// Logging out with it leaves the user's session intact.
	_, err = a.Logout(context.Background(), LogoutRequest{Token: res.AccessToken})
	qt.Assert(t, qt.IsNil(err))

	_, err = a.BrowserLogout(context.Background(), BrowserLogoutRequest{Token: res.AccessToken})
	qt.Assert(t, qt.IsNil(err))

	_, _, err = a.IntrospectToken(context.Background(), cookie)
	qt.Check(t, qt.IsNil(err))
}

func TestLoginRequiresConfidentialClientSecret(t *testing.T) {
	hash, err := password.Hash("s3cret")
	qt.Assert(t, qt.IsNil(err))

	a := newGrantsTestAuth(t, nil, nil, &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword}, AllowedAuthMethods: []string{client.AuthMethodPassword},
		ResponseMode: client.ResponseModeCookie, SecretHash: hash, TokenEndpointAuthMethod: client.TokenEndpointAuthClientSecret,
	})

	for _, secret := range []string{"", "wrong"} {
		_, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "ssr", Secret: secret}, Username: "alice", Password: "secret123"})
		qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidClient))
	}

	res, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "ssr", Secret: "s3cret"}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))
}

func TestLoginCapsScopeByClientScopes(t *testing.T) {
	cl := portalClient()
	cl.Scopes = []string{"openid"}
	a := newGrantsTestAuth(t, nil, nil, cl)

	login, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	// The user's full "openid profile" is narrowed for the token and the session alike.
	for _, tok := range []string{login.AccessToken, login.Cookie.Value} {
		info, _, err := a.IntrospectToken(context.Background(), tok)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(info.Scope, "openid"))
	}
}

func TestClientSecretImpliesConfidentialAuthentication(t *testing.T) {
	hash, err := password.Hash("s3cret")
	qt.Assert(t, qt.IsNil(err))

	// A secret registered without TokenEndpointAuthMethod must still be demanded.
	web := codeClient()
	web.Public, web.RequirePKCE, web.SecretHash = false, false, hash

	a := newGrantsTestAuth(t, nil, nil, portalClient(), web)
	cookie := login(t, a)

	redeem := func(secret string) error {
		_, err := a.AuthorizationCodeGrant(context.Background(), AuthorizationCodeGrantRequest{
			Credentials: ClientCredentials{ClientID: "web", Secret: secret}, Code: authorizeCode(t, a, cookie, "openid", ""),
			RedirectURI: "https://web.example/callback", CodeVerifier: pkceVerifier,
		})

		return err
	}

	qt.Check(t, qt.Equals(oauthErrorCode(t, redeem("")), ErrCodeInvalidClient))
	qt.Check(t, qt.IsNil(redeem("s3cret")))
}

func TestAuthorizeForcesPKCEForCredentiallessClient(t *testing.T) {
	// No secret, no key, no method: the client is public whatever its flags say.
	web := codeClient()
	web.Public, web.RequirePKCE = false, false

	a := newGrantsTestAuth(t, nil, nil, portalClient(), web)

	res, err := a.Authorize(context.Background(), AuthorizeRequest{
		ResponseType: "code", ClientID: "web", RedirectURI: "https://web.example/callback",
		Scope: "openid", State: "xyz", SessionToken: login(t, a),
	})
	qt.Assert(t, qt.IsNil(err))

	u, err := url.Parse(res.Redirect)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(u.Query().Get("error"), string(ErrCodeInvalidRequest)))
	qt.Check(t, qt.Equals(u.Query().Get("error_description"), "code_challenge is required"))
}

func TestClientCredentialsTokenIsNotResolvedToAUser(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)
	cfg := validConfig()
	cfg.Keys = keySetConfig(priv, pub)

	a := newGrantsTestAuth(t, cfg, nil, serviceClient(t, "s3cret"))

	res, err := a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{
		Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"}, Scope: "items:read",
	})
	qt.Assert(t, qt.IsNil(err))

	// No user "svc" exists; the client itself is the subject.
	info, err := a.ValidateJWTAccessToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.ID, "svc"))
	qt.Check(t, qt.Equals(info.ClientID, "svc"))
	qt.Check(t, qt.Equals(info.Scope, "items:read"))
}

func TestPrivateKeyJWTAssertionJTIIsScopedPerClient(t *testing.T) {
	keysPriv, keysPub := genTestRSAKeyPair(t)
	aPriv, aPub := genTestRSAKeyPair(t)
	bPriv, bPub := genTestRSAKeyPair(t)

	cfg := validConfig()
	cfg.Keys = keySetConfig(keysPriv, keysPub)

	assertionClient := func(id, pub string) *client.Client {
		return &client.Client{
			ID: id, GrantTypes: []string{"client_credentials"}, Scopes: []string{"items:read"},
			PublicKey: pub, AccessTokenType: client.AccessTokenTypeJWT,
			TokenEndpointAuthMethod: client.TokenEndpointAuthPrivateKeyJWT,
		}
	}

	a := newGrantsTestAuth(t, cfg, nil, assertionClient("svc-a", aPub), assertionClient("svc-b", bPub))

	grant := func(id, priv string) error {
		_, err := a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{
			Credentials: ClientCredentials{
				ClientID:      id,
				AssertionType: AssertionTypeJWTBearer,
				Assertion:     signAssertion(t, priv, id, "shared", []string{"https://issuer.example"}, time.Now().Add(time.Minute)),
			},
		})

		return err
	}

	// One client using a jti must not burn the same jti for another.
	qt.Assert(t, qt.IsNil(grant("svc-a", aPriv)))
	qt.Check(t, qt.IsNil(grant("svc-b", bPriv)))

	// Its own replay is still refused.
	qt.Check(t, qt.Equals(oauthErrorCode(t, grant("svc-a", aPriv)), ErrCodeInvalidClient))
}
