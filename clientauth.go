package auth

import (
	"cmp"
	"context"
	"slices"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/token"

	"azugo.io/core/http"
	"azugo.io/core/password"
	"github.com/golang-jwt/jwt/v5"
)

// AssertionTypeJWTBearer is the RFC 7523 client_assertion_type for private_key_jwt.
//
//nolint:gosec
const AssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// ClientCredentials carries the authentication material presented at a client-authenticated
// endpoint (/token, /introspect, /revoke).
type ClientCredentials struct {
	ClientID      string
	Secret        string
	AssertionType string
	Assertion     string
}

// AuthenticateClient resolves client credentials and enforces the client's registered
// TokenEndpointAuthMethod.
func (a *Auth) AuthenticateClient(ctx context.Context, creds ClientCredentials, baseURL, mountPath, tokenEndpoint string) (*client.Client, error) {
	cl, err := a.clients.GetClient(ctx, creds.ClientID)
	if err != nil {
		// Equivalent dummy work so an unknown client_id costs the same as a bad secret.
		password.VerifyEmpty(creds.Secret)

		return nil, NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "invalid client")
	}

	switch cl.TokenEndpointAuthMethod {
	case client.TokenEndpointAuthClientSecret:
		if cl.SecretHash == "" || creds.Secret == "" {
			password.VerifyEmpty(creds.Secret)

			return nil, NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "invalid client")
		}

		if ok, err := password.Verify(creds.Secret, cl.SecretHash); err != nil || !ok {
			return nil, NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "invalid client")
		}
	case client.TokenEndpointAuthPrivateKeyJWT:
		issuer := a.Issuer.URL(baseURL, mountPath)

		if err := a.verifyClientAssertion(ctx, cl, creds, []string{issuer, cmp.Or(tokenEndpoint, issuer+"/token")}); err != nil {
			return nil, err
		}
	case client.TokenEndpointAuthNone, "":
		if creds.Secret != "" || creds.Assertion != "" {
			return nil, NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "public client must not send credentials")
		}
	default:
		// An unrecognized configured method fails closed.
		return nil, NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "invalid client")
	}

	return cl, nil
}

// verifyClientAssertion verifies an RFC 7523 private_key_jwt client_assertion.
func (a *Auth) verifyClientAssertion(ctx context.Context, cl *client.Client, creds ClientCredentials, audiences []string) error {
	if creds.AssertionType != AssertionTypeJWTBearer || creds.Assertion == "" {
		return NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "client assertion required")
	}

	if cl.PublicKey == "" {
		return NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "invalid client")
	}

	pub, err := token.ParsePublicKeyPEM(cl.PublicKey)
	if err != nil {
		return NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "invalid client")
	}

	claims := jwt.MapClaims{}

	if _, err := jwt.ParseWithClaims(creds.Assertion, claims,
		func(*jwt.Token) (any, error) {
			return pub, nil
		},
		jwt.WithValidMethods([]string{
			token.AlgRS256, token.AlgRS384, token.AlgRS512,
			token.AlgES256, token.AlgES384, token.AlgES512,
		}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	); err != nil {
		return NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "invalid client assertion")
	}

	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)

	if iss != cl.ID || sub != cl.ID {
		return NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "invalid client assertion")
	}

	aud, err := claims.GetAudience()
	if err != nil || !slices.ContainsFunc(aud,
		func(got string) bool {
			return slices.Contains(audiences, got)
		},
	) {
		return NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "invalid client assertion audience")
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		return NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "client assertion jti required")
	}

	seen, err := a.assertions.Denied(ctx, jti)
	if err != nil {
		return NewOAuthErrorFrom(err)
	}

	if seen {
		return NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "client assertion replayed")
	}

	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "invalid client assertion")
	}

	iat, err := claims.GetIssuedAt()
	if err != nil || iat == nil {
		return NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "client assertion iat required")
	}

	if exp.Sub(iat.Time) > 5*time.Minute {
		return NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "client assertion lifetime too long")
	}

	if err := a.assertions.Deny(ctx, jti, time.Until(exp.Time)); err != nil {
		return NewOAuthErrorFrom(err)
	}

	return nil
}
