package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/internal/dpoptest"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

const (
	tokenURL     = "https://issuer.example/token"
	authorizeURL = "https://issuer.example/authorize"
)

// dpopLogin signs alice in through the portal client with a proof by key.
func dpopLogin(t *testing.T, a *Auth, key *dpoptest.Key) LoginResult {
	t.Helper()

	res, err := a.Login(context.Background(), LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", BaseURL: "https://issuer.example",
		DPoP: &DPoPProof{Proof: key.Proof(t, "POST", tokenURL, nil), Method: "POST", URL: tokenURL},
	})
	qt.Assert(t, qt.IsNil(err))

	return res
}

// boundKeyOf returns the thumbprint a reads tok as bound to.
func boundKeyOf(t *testing.T, a *Auth, tok string) string {
	t.Helper()

	jkt, err := a.boundKey(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))

	return jkt
}

// downKeyProvider is a key provider whose store is down.
type downKeyProvider struct{}

func (downKeyProvider) KeySet(context.Context) (*token.KeySet, error) {
	return nil, errors.New("keys unavailable")
}

func TestLoginWithDPoPProofBindsSessionTokens(t *testing.T) {
	cl := portalClient()
	cl.DPoPPolicy = client.DPoPPolicyRequired
	a := newGrantsTestAuth(t, nil, nil, cl, serviceClient(t, "s3cret"))
	key := dpoptest.NewKey(t)

	res := dpopLogin(t, a, key)
	qt.Check(t, qt.Equals(res.TokenType, "DPoP"))

	claims, err := a.codec.DecodeAccess(res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(claims.Confirmation))
	qt.Check(t, qt.Equals(claims.Confirmation.JKT, key.JKT))

	sess, err := a.sessions.Get(context.Background(), claims.SessionID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.DPoPJKT, key.JKT))

	out, err := a.Introspect(context.Background(), IntrospectRequest{Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"}, Token: res.AccessToken})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(out.Active))
	qt.Check(t, qt.Equals(out.TokenType, "DPoP"))
	qt.Check(t, qt.DeepEquals(out.Confirmation, &token.Confirmation{JKT: key.JKT}))
}

func TestLoginOfOptionalClientBindsOnlyTheToken(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient())
	key := dpoptest.NewKey(t)

	res := dpopLogin(t, a, key)
	qt.Check(t, qt.Equals(res.TokenType, "DPoP"))

	claims, err := a.codec.DecodeAccess(res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(claims.Confirmation))
	qt.Check(t, qt.Equals(claims.Confirmation.JKT, key.JKT))

	// The session stays unbound, so the client's proof-less silent re-auth keeps working.
	sess, err := a.sessions.Get(context.Background(), claims.SessionID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.DPoPJKT, ""))

	res, err = a.Refresh(context.Background(), RefreshRequest{Token: res.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.TokenType, "Bearer"))
}

func TestLoginWithoutProofIssuesBearer(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient())

	res, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.TokenType, "Bearer"))
}

func TestDPoPPolicyRequiredRefusesMissingProof(t *testing.T) {
	cl := portalClient()
	cl.DPoPPolicy = client.DPoPPolicyRequired
	a := newGrantsTestAuth(t, nil, nil, cl)

	_, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidDPoPProof))
}

func TestMissingProofCarriesNonceForNoncePolicy(t *testing.T) {
	for _, policy := range []client.DPoPPolicy{client.DPoPPolicyRequired, client.DPoPPolicyNonce} {
		cl := portalClient()
		cl.DPoPPolicy = policy
		a := newGrantsTestAuth(t, nil, nil, cl)

		_, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123"})

		oe, ok := errors.AsType[*OAuthError](err)
		qt.Assert(t, qt.IsTrue(ok))
		qt.Check(t, qt.Equals(oe.Code, ErrCodeInvalidDPoPProof))

		// Only the nonce-policy client is told the nonce with the refusal.
		qt.Check(t, qt.Equals(oe.dpopNonce != "", policy == client.DPoPPolicyNonce), qt.Commentf("%s", policy))
	}
}

func TestLoginRefusesInvalidProof(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient())
	key := dpoptest.NewKey(t)

	_, err := a.Login(context.Background(), LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123",
		DPoP: &DPoPProof{Proof: key.Proof(t, "POST", "https://issuer.example/other", nil), Method: "POST", URL: tokenURL},
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidDPoPProof))
}

func TestDPoPNonceMode(t *testing.T) {
	cl := portalClient()
	cl.DPoPPolicy = client.DPoPPolicyNonce
	a := newGrantsTestAuth(t, nil, nil, cl)
	key := dpoptest.NewKey(t)

	req := LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123",
		DPoP: &DPoPProof{Proof: key.Proof(t, "POST", tokenURL, nil), Method: "POST", URL: tokenURL},
	}

	_, err := a.Login(context.Background(), req)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUseDPoPNonce))

	nonce := a.DPoPNonce()
	qt.Assert(t, qt.Not(qt.Equals(nonce, "")))

	req.DPoP.Proof = key.Proof(t, "POST", tokenURL, map[string]any{"nonce": nonce})

	res, err := a.Login(context.Background(), req)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.TokenType, "DPoP"))
	qt.Check(t, qt.Equals(res.DPoPNonce, nonce))

	// Other clients bind without a nonce.
	b := newGrantsTestAuth(t, nil, nil, portalClient())

	req.DPoP.Proof = key.Proof(t, "POST", tokenURL, nil)

	res, err = b.Login(context.Background(), req)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.DPoPNonce, ""))
}

func TestStepCompletionCarriesNonce(t *testing.T) {
	cl := mfaClient(client.MFAPolicyDisabled)
	cl.DPoPPolicy = client.DPoPPolicyNonce
	a, users := newAccountTestAuth(t, cl)

	u := users.users["alice"]
	u.RequiresPasswordChange = true
	users.users["alice"] = u

	key := dpoptest.NewKey(t)
	req := alice("")
	req.DPoP = &DPoPProof{Proof: key.Proof(t, "POST", tokenURL, map[string]any{"nonce": a.DPoPNonce()}), Method: "POST", URL: tokenURL}

	held := loginAs(t, a, req)
	qt.Assert(t, qt.Equals(held.Status, session.StatusPendingPasswordChange))
	qt.Check(t, qt.Not(qt.Equals(held.DPoPNonce, "")))

	// The tokens issued by the step's completion come with the nonce for the next proof.
	done, err := a.ChangePassword(context.Background(), PasswordChangeRequest{Token: held.StepToken, NewPassword: "brandnew1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.TokenType, "DPoP"))
	qt.Check(t, qt.Not(qt.Equals(done.DPoPNonce, "")))
}

func TestRefreshOfBoundSessionNeedsProofByItsKey(t *testing.T) {
	cl := portalClient()
	cl.DPoPPolicy = client.DPoPPolicyRequired
	a := newGrantsTestAuth(t, nil, nil, cl)
	key := dpoptest.NewKey(t)
	cookie := dpopLogin(t, a, key).Cookie.Value

	_, err := a.Refresh(context.Background(), RefreshRequest{Token: cookie})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidDPoPProof))

	_, err = a.Refresh(context.Background(), RefreshRequest{
		Token: cookie,
		DPoP:  &DPoPProof{Proof: dpoptest.NewKey(t).Proof(t, "POST", authorizeURL, nil), Method: "POST", URL: authorizeURL},
	})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidDPoPProof))

	// The refused attempts left the cookie usable.
	res, err := a.Refresh(context.Background(), RefreshRequest{
		Token: cookie,
		DPoP:  &DPoPProof{Proof: key.Proof(t, "POST", authorizeURL, nil), Method: "POST", URL: authorizeURL},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.TokenType, "DPoP"))

	claims, err := a.codec.DecodeAccess(res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(claims.Confirmation.JKT, key.JKT))
}

func TestRefreshOfOptionalClientBindsOnlyTheToken(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient())
	key := dpoptest.NewKey(t)
	cookie := login(t, a)

	res, err := a.Refresh(context.Background(), RefreshRequest{
		Token: cookie,
		DPoP:  &DPoPProof{Proof: key.Proof(t, "POST", authorizeURL, nil), Method: "POST", URL: authorizeURL},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.TokenType, "DPoP"))

	claims, err := a.codec.DecodeAccess(res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(claims.Confirmation.JKT, key.JKT))

	// The session stays unbound, so a refresh without a proof keeps working.
	sess, err := a.sessions.Get(context.Background(), claims.SessionID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.DPoPJKT, ""))

	res, err = a.Refresh(context.Background(), RefreshRequest{Token: res.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.TokenType, "Bearer"))
}

func TestDPoPPolicyRequiredWithholdsTokensOfUnboundSession(t *testing.T) {
	cl := portalClient()
	cl.DPoPPolicy = client.DPoPPolicyRequired
	a := newGrantsTestAuth(t, nil, nil, cl)

	// A sign-in without a proof, as after registration or a password reset.
	res, err := a.startSession(context.Background(), &session.Session{UserID: "u1", ClientID: "spa", Scope: "openid"}, cl, "", acrRequest{}, "", "", "")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.AccessToken, ""))
	qt.Assert(t, qt.IsNotNil(res.Cookie))

	res, err = a.Refresh(context.Background(), RefreshRequest{
		Token: res.Cookie.Value,
		DPoP:  &DPoPProof{Proof: dpoptest.NewKey(t).Proof(t, "POST", authorizeURL, nil), Method: "POST", URL: authorizeURL},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Not(qt.Equals(res.AccessToken, "")))
	qt.Check(t, qt.Equals(res.TokenType, "DPoP"))

	// From now on the session refreshes only with that key.
	_, err = a.Refresh(context.Background(), RefreshRequest{Token: res.Cookie.Value})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidDPoPProof))
}

func TestClientCredentialsGrantBindsJWT(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)
	cfg := validConfig()
	cfg.Keys = keySetConfig(priv, pub)

	a := newGrantsTestAuth(t, cfg, nil, serviceClient(t, "s3cret"))
	key := dpoptest.NewKey(t)

	res, err := a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{
		Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"},
		DPoP:        &DPoPProof{Proof: key.Proof(t, "POST", tokenURL, nil), Method: "POST", URL: tokenURL},
		BaseURL:     "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.TokenType, "DPoP"))

	set, err := a.Keys().KeySet(context.Background())
	qt.Assert(t, qt.IsNil(err))

	claims, err := token.VerifyAccessToken(set, res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(claims.JKT, key.JKT))
	qt.Check(t, qt.Equals(boundKeyOf(t, a, res.AccessToken), key.JKT))

	out, err := a.Introspect(context.Background(), IntrospectRequest{Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"}, Token: res.AccessToken})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(out.TokenType, "DPoP"))
	qt.Check(t, qt.DeepEquals(out.Confirmation, &token.Confirmation{JKT: key.JKT}))
}

func TestBoundKeyNeedsValidJWTSignature(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)
	cfg := validConfig()
	cfg.Keys = keySetConfig(priv, pub)

	a := newGrantsTestAuth(t, cfg, nil, serviceClient(t, "s3cret"))
	key := dpoptest.NewKey(t)

	res, err := a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{
		Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"},
		DPoP:        &DPoPProof{Proof: key.Proof(t, "POST", tokenURL, nil), Method: "POST", URL: tokenURL},
		BaseURL:     "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(boundKeyOf(t, a, res.AccessToken), key.JKT))

	// A binding is read only from a token this server signed.
	parts := strings.Split(res.AccessToken, ".")
	parts[2] = "x"
	qt.Check(t, qt.Equals(boundKeyOf(t, a, strings.Join(parts, ".")), ""))

	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"at+jwt"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"cnf":{"jkt":"`+key.JKT+`"}}`)) + ".x"
	qt.Check(t, qt.Equals(boundKeyOf(t, a, forged), ""))
}

func TestRegisterSignInNeedsProofForRequiredPolicy(t *testing.T) {
	cl := registeringClient()
	cl.DPoPPolicy = client.DPoPPolicyRequired
	a, users := newAccountTestAuth(t, cl)

	// Without a proof no account is created, so the client can retry with one.
	_, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Password: "pw123456", IP: "10.0.0.9"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidDPoPProof))
	qt.Check(t, qt.Equals(users.users["bob"].ID, ""))

	key := dpoptest.NewKey(t)

	reg, err := a.Register(context.Background(), RegisterRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Password: "pw123456", IP: "10.0.0.9",
		DPoP: &DPoPProof{Proof: key.Proof(t, "POST", tokenURL, nil), Method: "POST", URL: tokenURL},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(reg.Login))
	qt.Check(t, qt.Equals(reg.Login.TokenType, "DPoP"))
	qt.Check(t, qt.Not(qt.Equals(reg.Login.AccessToken, "")))

	claims, err := a.codec.DecodeAccess(reg.Login.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(claims.Confirmation.JKT, key.JKT))

	sess, err := a.sessions.Get(context.Background(), claims.SessionID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.DPoPJKT, key.JKT))
}

func TestResetPasswordNeedsProofForRequiredPolicy(t *testing.T) {
	cl := mfaClient(client.MFAPolicyDisabled)
	cl.DPoPPolicy = client.DPoPPolicyRequired
	a, users := newAccountTestAuth(t, cl)

	res := requestReset(t, a, "alice@example.com", "")
	secret := users.awaitDelivery(t)

	// A decoy refuses a missing proof the same way, and neither consumes the reset.
	decoy := requestReset(t, a, "nobody@example.com", "")

	for _, tok := range []string{res.Token, decoy.Token} {
		_, err := a.ResetPassword(context.Background(), PasswordResetConfirmRequest{Token: tok, Response: map[string]any{"token": secret}, NewPassword: "brandnew1"})
		qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidDPoPProof))
	}

	key := dpoptest.NewKey(t)

	done, err := a.ResetPassword(context.Background(), PasswordResetConfirmRequest{
		Token: res.Token, Response: map[string]any{"token": secret}, NewPassword: "brandnew1",
		DPoP: &DPoPProof{Proof: key.Proof(t, "POST", tokenURL, nil), Method: "POST", URL: tokenURL},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.TokenType, "DPoP"))
	qt.Check(t, qt.Not(qt.Equals(done.AccessToken, "")))

	claims, err := a.codec.DecodeAccess(done.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(claims.Confirmation.JKT, key.JKT))
}

func TestDPoPProofWindowDefaultsApartFromClockSkew(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient())

	// A strict clock skew leaves the proof window at its own default.
	qt.Check(t, qt.Equals(a.config.ClockSkew, time.Duration(0)))
	qt.Check(t, qt.Equals(a.config.DPoPProofWindow, time.Minute))

	key := dpoptest.NewKey(t)
	proof := key.Proof(t, "POST", tokenURL, map[string]any{"iat": time.Now().Add(-30 * time.Second).Unix()})

	res, err := a.Login(context.Background(), LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123",
		DPoP: &DPoPProof{Proof: proof, Method: "POST", URL: tokenURL},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.TokenType, "DPoP"))
}

func TestReadAccessTokenFailsClosedWithoutKeys(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)
	cfg := validConfig()
	cfg.Keys = keySetConfig(priv, pub)

	a := newGrantsTestAuth(t, cfg, nil, serviceClient(t, "s3cret"))
	key := dpoptest.NewKey(t)

	res, err := a.ClientCredentialsGrant(context.Background(), ClientCredentialsGrantRequest{
		Credentials: ClientCredentials{ClientID: "svc", Secret: "s3cret"},
		DPoP:        &DPoPProof{Proof: key.Proof(t, "POST", tokenURL, nil), Method: "POST", URL: tokenURL},
		BaseURL:     "https://issuer.example",
	})
	qt.Assert(t, qt.IsNil(err))

	app := azugo.NewTestApp()
	app.Start(t)
	defer app.Stop()

	app.Get("/", func(ctx *azugo.Context) {
		_, err := a.ReadAccessToken(ctx)
		if oe, ok := errors.AsType[*OAuthError](err); ok {
			ctx.Text(string(oe.Code))

			return
		}

		ctx.Text("ok")
	})

	tc := app.TestClient()

	// While the key provider is down a bound token presented as a bearer token is refused, not read as unbound.
	a.keys = downKeyProvider{}

	resp, err := tc.Get("/", tc.WithHeader("Authorization", "Bearer "+res.AccessToken))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(body), string(ErrCodeServerError)))
}

func TestLoginChecksThrottleBeforeProof(t *testing.T) {
	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a := newGrantsTestAuth(t, cfg, nil, portalClient())
	bad := &DPoPProof{Proof: "not-a-proof", Method: "POST", URL: tokenURL}

	login := func(password string, proof *DPoPProof) error {
		_, err := a.Login(context.Background(), LoginRequest{
			Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: password, IP: "203.0.113.9", DPoP: proof,
		})

		return err
	}

	// A refused proof is no guess, so it never counts towards the lockout.
	for range 3 {
		qt.Check(t, qt.Equals(oauthErrorCode(t, login("secret123", bad)), ErrCodeInvalidDPoPProof))
	}

	qt.Assert(t, qt.IsNil(login("secret123", nil)))

	qt.Check(t, qt.Equals(oauthErrorCode(t, login("wrong", nil)), ErrCodeInvalidGrant))
	qt.Check(t, qt.Equals(oauthErrorCode(t, login("wrong", nil)), ErrCodeInvalidGrant))

	// Locked out, the proof is not even looked at.
	qt.Check(t, qt.Equals(oauthErrorCode(t, login("secret123", bad)), ErrCodeSlowDown))
}

func TestAuthorizationCodeGrantChecksProofBeforeConsumingCode(t *testing.T) {
	web := codeClient()
	web.DPoPPolicy = client.DPoPPolicyNonce

	a := newGrantsTestAuth(t, nil, nil, portalClient(), web)
	key := dpoptest.NewKey(t)
	codeVal := authorizeCode(t, a, login(t, a), "profile", "")

	req := AuthorizationCodeGrantRequest{
		Credentials:  ClientCredentials{ClientID: "web"},
		Code:         codeVal,
		RedirectURI:  "https://web.example/callback",
		CodeVerifier: pkceVerifier,
		DPoP:         &DPoPProof{Proof: key.Proof(t, "POST", tokenURL, nil), Method: "POST", URL: tokenURL},
	}

	_, err := a.AuthorizationCodeGrant(context.Background(), req)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUseDPoPNonce))

	// The retry with the nonce redeems the same code.
	req.DPoP.Proof = key.Proof(t, "POST", tokenURL, map[string]any{"nonce": a.DPoPNonce()})

	res, err := a.AuthorizationCodeGrant(context.Background(), req)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.TokenType, "DPoP"))
	qt.Check(t, qt.Equals(boundKeyOf(t, a, res.AccessToken), key.JKT))
}

func TestAuthorizationCodeBoundToDPoPJKT(t *testing.T) {
	a := newGrantsTestAuth(t, nil, nil, portalClient(), codeClient())
	key := dpoptest.NewKey(t)
	cookie := login(t, a)

	authorize := func(jkt string) string {
		res, err := a.Authorize(context.Background(), AuthorizeRequest{
			ResponseType: "code", ClientID: "web", RedirectURI: "https://web.example/callback", Scope: "profile", State: "xyz",
			CodeChallenge: pkceChallenge, CodeChallengeMethod: "S256", DPoPJKT: jkt, SessionToken: cookie,
		})
		qt.Assert(t, qt.IsNil(err))

		u, err := url.Parse(res.Redirect)
		qt.Assert(t, qt.IsNil(err))

		return u.Query().Get("code")
	}

	redeem := func(codeVal string, key *dpoptest.Key) (TokenResult, error) {
		req := AuthorizationCodeGrantRequest{
			Credentials: ClientCredentials{ClientID: "web"}, Code: codeVal, RedirectURI: "https://web.example/callback", CodeVerifier: pkceVerifier,
		}
		if key != nil {
			req.DPoP = &DPoPProof{Proof: key.Proof(t, "POST", tokenURL, nil), Method: "POST", URL: tokenURL}
		}

		return a.AuthorizationCodeGrant(context.Background(), req)
	}

	// A malformed thumbprint is refused at the authorization endpoint.
	res, err := a.Authorize(context.Background(), AuthorizeRequest{
		ResponseType: "code", ClientID: "web", RedirectURI: "https://web.example/callback", Scope: "profile", State: "xyz",
		CodeChallenge: pkceChallenge, CodeChallengeMethod: "S256", DPoPJKT: "not-a-thumbprint", SessionToken: cookie,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(res.Redirect, "error=invalid_request"))

	_, err = redeem(authorize(key.JKT), nil)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	_, err = redeem(authorize(key.JKT), dpoptest.NewKey(t))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	tr, err := redeem(authorize(key.JKT), key)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(boundKeyOf(t, a, tr.AccessToken), key.JKT))
}

func TestPendingStepKeepsOptionalClientBinding(t *testing.T) {
	a, _ := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled))
	key := dpoptest.NewKey(t)

	held := loginAs(t, a, LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "fresh", Password: "changeme",
		DPoP: &DPoPProof{Proof: key.Proof(t, "POST", tokenURL, nil), Method: "POST", URL: tokenURL},
	})
	qt.Assert(t, qt.Equals(held.Status, session.StatusPendingPasswordChange))

	// The step's completion issues the token bound to the key presented at login.
	done, err := a.ChangePassword(context.Background(), PasswordChangeRequest{Token: held.StepToken, NewPassword: "brandnew1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.TokenType, "DPoP"))

	claims, err := a.codec.DecodeAccess(done.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(claims.Confirmation))
	qt.Check(t, qt.Equals(claims.Confirmation.JKT, key.JKT))

	// The session of an optional-policy client stays unbound.
	sess, err := a.sessions.Get(context.Background(), claims.SessionID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.DPoPJKT, ""))
}
