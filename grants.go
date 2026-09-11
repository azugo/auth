package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/code"
	"azugo.io/auth/event"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/core/http"
)

// tokenTypeBearer is the RFC 6750 token_type value.
const tokenTypeBearer = "Bearer"

// AuthorizeRequest carries an OIDC authorization request (GET /authorize, response_type=code).
type AuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	ACRValues           string
	CodeChallenge       string
	CodeChallengeMethod string
	// SessionToken is the presented session cookie establishing the user's identity.
	SessionToken string
}

// AuthorizeResult carries the redirect the caller should perform.
type AuthorizeResult struct {
	Redirect string
}

// Authorize handles the authorization-code flow: it validates the request, establishes the
// user from the session cookie, mints a single-use code and returns the redirect.
func (a *Auth) Authorize(ctx context.Context, in AuthorizeRequest) (AuthorizeResult, error) {
	cl, err := a.clients.GetClient(ctx, in.ClientID)
	if err != nil {
		return AuthorizeResult{}, NewOAuthErrorFrom(err)
	}

	if in.RedirectURI == "" || !slices.Contains(cl.RedirectURIs, in.RedirectURI) {
		return AuthorizeResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "redirect_uri is not registered for the client")
	}

	// The redirect_uri is validated - protocol errors from here on redirect back to it.
	if in.ResponseType != "code" {
		return authorizeErrorRedirect(in, ErrCodeUnsupportedResponseType, "only response_type=code is supported"), nil
	}

	if !cl.GrantTypeAllowed(client.GrantTypeAuthorizationCode) {
		return authorizeErrorRedirect(in, ErrCodeUnauthorizedClient, "client is not allowed to use the authorization_code grant"), nil
	}

	if cl.RequirePKCE || cl.Public {
		if in.CodeChallenge == "" {
			return authorizeErrorRedirect(in, ErrCodeInvalidRequest, "code_challenge is required"), nil
		}
	}

	if in.CodeChallenge != "" && in.CodeChallengeMethod != "S256" {
		return authorizeErrorRedirect(in, ErrCodeInvalidRequest, "only code_challenge_method=S256 is supported"), nil
	}

	if in.CodeChallenge != "" && !validPKCEValue(in.CodeChallenge) {
		return authorizeErrorRedirect(in, ErrCodeInvalidRequest, "code_challenge must be 43-128 unreserved characters"), nil
	}

	info, sess, err := a.IntrospectToken(ctx, in.SessionToken)
	if err != nil {
		return AuthorizeResult{}, NewOAuthErrorFrom(ErrLoginRequired)
	}

	// validate against client allowed scopes
	available := sess.Scope

	if len(cl.Scopes) > 0 {
		fields := make([]string, 0, len(cl.Scopes))

		for _, v := range cl.Scopes {
			if scopeContains(sess.Scope, v) {
				fields = append(fields, v)
			}
		}

		available = strings.Join(fields, " ")
	}

	scope, ok := grantedScope(in.Scope, available)
	if !ok {
		return authorizeErrorRedirect(in, ErrCodeInvalidScope, "requested scope exceeds the granted scope"), nil
	}

	val, err := newJTI()
	if err != nil {
		return AuthorizeResult{}, NewOAuthErrorFrom(err)
	}

	rec := &code.AuthorizationCode{
		Code:                val,
		ClientID:            cl.ID,
		UserID:              info.ID,
		SessionID:           sess.ID,
		RedirectURI:         in.RedirectURI,
		Scope:               scope,
		Nonce:               in.Nonce,
		ACRValues:           strings.Fields(in.ACRValues),
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(a.config.CodeTTL),
	}

	if err := a.codes.Save(ctx, rec); err != nil {
		return AuthorizeResult{}, NewOAuthErrorFrom(err)
	}

	return AuthorizeResult{
		Redirect: appendQuery(in.RedirectURI, url.Values{
			"code":  {val},
			"state": {in.State},
		}),
	}, nil
}

// TokenResult is the RFC 6749 §5.1 access token response for the authorization_code and
// client_credentials grants.
type TokenResult struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

// AuthorizationCodeGrantRequest carries an authorization_code redemption.
type AuthorizationCodeGrantRequest struct {
	Credentials   ClientCredentials
	Code          string
	RedirectURI   string
	CodeVerifier  string
	BaseURL       string
	MountPath     string
	TokenEndpoint string
	IP            string
}

// AuthorizationCodeGrant redeems a single-use authorization code for tokens. A replayed code
// revokes the bound session.
func (a *Auth) AuthorizationCodeGrant(ctx context.Context, in AuthorizationCodeGrantRequest) (TokenResult, error) {
	cl, err := a.AuthenticateClient(ctx, in.Credentials, in.BaseURL, in.MountPath, in.TokenEndpoint)
	if err != nil {
		return TokenResult{}, err
	}

	if !cl.GrantTypeAllowed(client.GrantTypeAuthorizationCode) {
		return TokenResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeUnauthorizedClient, "client is not allowed to use the authorization_code grant")
	}

	rec, err := a.codes.Consume(ctx, in.Code)

	switch {
	case errors.Is(err, code.ErrReplayed) && rec != nil:
		if err := a.sessions.Revoke(ctx, rec.SessionID); err != nil && !errors.Is(err, session.ErrNotFound) {
			return TokenResult{}, NewOAuthErrorFrom(err)
		}

		// Revoke issued token
		if rec.IssuedTokenID != "" {
			if err := a.denied.Deny(ctx, rec.IssuedTokenID, time.Until(rec.IssuedTokenExpiresAt)); err != nil {
				return TokenResult{}, NewOAuthErrorFrom(err)
			}
		}

		a.emit(ctx, event.Event{Type: event.TypeSessionRevoked, UserID: rec.UserID, ClientID: cl.ID, IP: in.IP, Detail: map[string]any{"reason": "authorization code replayed"}})

		return TokenResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "invalid authorization code")
	case err != nil:
		return TokenResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "invalid authorization code")
	}

	if rec.ClientID != cl.ID {
		return TokenResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "invalid authorization code")
	}

	if in.RedirectURI != rec.RedirectURI {
		return TokenResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "redirect_uri does not match the authorization request")
	}

	if rec.CodeChallenge != "" {
		if in.CodeVerifier == "" {
			return TokenResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "code_verifier is required")
		}

		if !validPKCEValue(in.CodeVerifier) {
			return TokenResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "code_verifier must be 43-128 unreserved characters")
		}

		// PKCE: BASE64URL(SHA256(code_verifier)) must match the bound challenge
		sum := sha256.Sum256([]byte(in.CodeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(sum[:])

		if subtle.ConstantTimeCompare([]byte(computed), []byte(rec.CodeChallenge)) != 1 {
			return TokenResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "code_verifier does not match the challenge")
		}
	}

	sess, err := a.sessions.Get(ctx, rec.SessionID)
	if err != nil || !sess.Active() {
		return TokenResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "session is no longer active")
	}

	at, atID, err := a.issueAccessToken(ctx, sess, cl, rec.Scope, in.BaseURL, in.MountPath)
	if err != nil {
		return TokenResult{}, err
	}

	if cl.AccessTokenType == client.AccessTokenTypeJWT {
		if err := a.codes.BindIssuedToken(ctx, in.Code, atID, time.Now().Add(a.config.AccessTokenTTL)); err != nil {
			return TokenResult{}, NewOAuthErrorFrom(err)
		}
	}

	res := TokenResult{
		AccessToken: at,
		TokenType:   tokenTypeBearer,
		ExpiresIn:   int(a.config.AccessTokenTTL.Seconds()),
		Scope:       rec.Scope,
	}

	if a.keys != nil && scopeContains(rec.Scope, "openid") {
		idToken, err := a.issueIDToken(ctx, sess, cl, in.BaseURL, in.MountPath, rec.Nonce)
		if err != nil {
			return TokenResult{}, NewOAuthErrorFrom(err)
		}

		res.IDToken = idToken
	}

	a.emit(ctx, event.Event{Type: event.TypeTokenIssued, UserID: sess.UserID, ClientID: cl.ID, IP: in.IP, Detail: map[string]any{"grant_type": client.GrantTypeAuthorizationCode}})

	return res, nil
}

// ClientCredentialsGrantRequest carries a client_credentials request.
type ClientCredentialsGrantRequest struct {
	Credentials   ClientCredentials
	Scope         string
	BaseURL       string
	MountPath     string
	TokenEndpoint string
	IP            string
}

// ClientCredentialsGrant issues a JWT access token to a confidential client without a user or
// session.
func (a *Auth) ClientCredentialsGrant(ctx context.Context, in ClientCredentialsGrantRequest) (TokenResult, error) {
	cl, err := a.AuthenticateClient(ctx, in.Credentials, in.BaseURL, in.MountPath, in.TokenEndpoint)
	if err != nil {
		return TokenResult{}, err
	}

	if !cl.GrantTypeAllowed("client_credentials") {
		return TokenResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeUnauthorizedClient, "client is not allowed to use the client_credentials grant")
	}

	if cl.Public || cl.TokenEndpointAuthMethod == client.TokenEndpointAuthNone || cl.TokenEndpointAuthMethod == "" {
		return TokenResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeUnauthorizedClient, "client_credentials requires a confidential client")
	}

	if cl.AccessTokenType != client.AccessTokenTypeJWT {
		return TokenResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "client_credentials requires jwt access tokens")
	}

	if a.keys == nil {
		return TokenResult{}, NewOAuthError(http.StatusInternalServerError, ErrCodeServerError, "no key provider configured")
	}

	scope, ok := grantedScope(in.Scope, strings.Join(cl.Scopes, " "))
	if !ok {
		return TokenResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidScope, "requested scope exceeds the registered scope")
	}

	at, _, err := a.signAccessToken(ctx, cl.ID, cl, scope, in.BaseURL, in.MountPath)
	if err != nil {
		return TokenResult{}, err
	}

	a.emit(ctx, event.Event{Type: event.TypeTokenIssued, ClientID: cl.ID, IP: in.IP, Detail: map[string]any{"grant_type": "client_credentials"}})

	return TokenResult{
		AccessToken: at,
		TokenType:   tokenTypeBearer,
		ExpiresIn:   int(a.config.AccessTokenTTL.Seconds()),
		Scope:       scope,
	}, nil
}

// issueAccessToken mints the access token for session, returning the token and its JTI.
func (a *Auth) issueAccessToken(ctx context.Context, sess *session.Session, cl *client.Client, scope, baseURL, mountPath string) (string, string, error) {
	if cl.AccessTokenType == client.AccessTokenTypeJWT {
		if a.keys == nil {
			return "", "", NewOAuthError(http.StatusInternalServerError, ErrCodeServerError, "no key provider configured")
		}

		return a.signAccessToken(ctx, sess.UserID, cl, scope, baseURL, mountPath)
	}

	now := time.Now()

	atJTI, err := newJTI()
	if err != nil {
		return "", "", NewOAuthErrorFrom(err)
	}

	if err := a.jti.Issue(ctx, atJTI, sess.ID, a.config.AccessTokenTTL); err != nil {
		return "", "", NewOAuthErrorFrom(err)
	}

	at, err := a.codec.Encrypt(token.AccessClaims{
		Type:      token.TypeAccessToken,
		SessionID: sess.ID,
		TokenID:   atJTI,
		ClientID:  cl.ID,
		Scope:     scope,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(a.config.AccessTokenTTL).Unix(),
	})
	if err != nil {
		return "", "", NewOAuthErrorFrom(err)
	}

	return at, atJTI, nil
}

// signAccessToken mints a signed JWT access token for subject using the primary signing key,
// returning the token and its JTI.
func (a *Auth) signAccessToken(ctx context.Context, subject string, cl *client.Client, scope, baseURL, mountPath string) (string, string, error) {
	keys, err := a.keys.KeySet(ctx)
	if err != nil {
		return "", "", NewOAuthErrorFrom(err)
	}

	jtiVal, err := newJTI()
	if err != nil {
		return "", "", NewOAuthErrorFrom(err)
	}

	now := time.Now()

	at, err := token.SignAccessToken(keys.Primary, token.AccessTokenClaims{
		Issuer:    a.Issuer.URL(baseURL, mountPath),
		Subject:   subject,
		ClientID:  cl.ID,
		Scope:     scope,
		TokenID:   jtiVal,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(a.config.AccessTokenTTL).Unix(),
	})
	if err != nil {
		return "", "", NewOAuthErrorFrom(err)
	}

	return at, jtiVal, nil
}

// validPKCEValue reports whether v is a valid RFC 7636 code_verifier or code_challenge:
// 43-128 unreserved characters.
func validPKCEValue(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}

	for _, c := range []byte(v) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}

	return true
}

// grantedScope intersects the requested scope with the available scope.
func grantedScope(requested, available string) (string, bool) {
	if requested == "" {
		return available, true
	}

	for v := range strings.FieldsSeq(requested) {
		if !scopeContains(available, v) {
			return "", false
		}
	}

	return requested, true
}

// authorizeErrorRedirect builds the RFC 6749 §4.1.2.1 error redirect for a validated
// redirect_uri.
func authorizeErrorRedirect(in AuthorizeRequest, errCode ErrorCode, description string) AuthorizeResult {
	return AuthorizeResult{
		Redirect: appendQuery(in.RedirectURI, url.Values{
			"error":             {string(errCode)},
			"error_description": {description},
			"state":             {in.State},
		}),
	}
}

// appendQuery appends params to uri, dropping empty values.
func appendQuery(uri string, params url.Values) string {
	for k, vs := range params {
		if len(vs) == 0 || vs[0] == "" {
			delete(params, k)
		}
	}

	sep := "?"
	if strings.Contains(uri, "?") {
		sep = "&"
	}

	return uri + sep + params.Encode()
}
