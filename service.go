package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/event"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/core/http"
	"azugo.io/core/paginator"
)

// detailKeyUsername is the event detail key for username/password login flows.
const detailKeyUsername = "username"

// CookieDirective describes how to set or clear the session cookie.
//
// A negative MaxAge deletes the cookie.
type CookieDirective struct {
	Name, Value, Path, Domain string
	MaxAge                    int
	Secure, HTTPOnly          bool
	SameSite                  string
}

// LoginResult is returned by Login and Refresh based on client mode and configuration.
type LoginResult struct {
	Status      session.Status
	Cookie      *CookieDirective
	AccessToken string
	// IDToken is set only for a client.ResponseModeJSON client whose granted scope contains
	// "openid".
	IDToken   string
	ExpiresIn int
	// ReturnTo is the local redirect target for a client.ResponseModeRedirect client.
	ReturnTo string
}

// LoginRequest carries the password-grant credentials and the request-derived values.
type LoginRequest struct {
	ClientID   string
	Username   string
	Password   string
	ReturnTo   string
	RequestTLS bool
	BaseURL    string
	MountPath  string
	// IP is the caller's remote address.
	IP string
}

// RefreshRequest carries the presented refresh token and the request-derived values.
type RefreshRequest struct {
	Token      string
	ReturnTo   string
	RequestTLS bool
	BaseURL    string
	MountPath  string
}

// LogoutRequest carries the presented token and the request-derived values.
type LogoutRequest struct {
	Token      string
	RequestTLS bool
	BasePath   string
	MountPath  string
}

// LogoutResult is returned by Logout.
type LogoutResult struct {
	ClearCookie *CookieDirective
}

// Login authenticates a password-grant request, creates an active session and returns the
// directives the caller should apply.
func (a *Auth) Login(ctx context.Context, in LoginRequest) (LoginResult, error) {
	cl, err := a.clients.GetClient(ctx, in.ClientID)
	if err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	if !cl.GrantTypeAllowed(client.GrantTypePassword) || !cl.AuthMethodAllowed(client.AuthMethodPassword) {
		return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeUnauthorizedClient, "client is not allowed to use the password grant")
	}

	// Throttle keys combine the stable identity with the IP so neither a single account nor
	// a single source can be brute-forced.
	throttleKeys := make([]string, 0, 2)

	if in.Username != "" {
		throttleKeys = append(throttleKeys, "pwd:"+in.Username)
	}

	if in.IP != "" {
		throttleKeys = append(throttleKeys, "ip:"+in.IP)
	}

	for _, key := range throttleKeys {
		ok, retryAfter, err := a.throttle.Allow(ctx, key)
		if err != nil {
			return LoginResult{}, NewOAuthErrorFrom(err)
		}

		if !ok {
			a.emit(ctx, event.Event{Type: event.TypeLockout, ClientID: cl.ID, IP: in.IP, Detail: map[string]any{"key": key}})

			return LoginResult{}, NewThrottledError(retryAfter)
		}
	}

	info, err := a.users.Authenticate(ctx, in.Username, in.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			for _, key := range throttleKeys {
				_ = a.throttle.Fail(ctx, key)
			}
		}

		a.emit(ctx, event.Event{Type: event.TypeLoginFailure, ClientID: cl.ID, IP: in.IP, Detail: map[string]any{detailKeyUsername: in.Username}})

		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	for _, key := range throttleKeys {
		_ = a.throttle.Reset(ctx, key)
	}

	a.emit(ctx, event.Event{Type: event.TypeLoginSuccess, UserID: info.ID, ClientID: cl.ID, IP: in.IP, Detail: map[string]any{detailKeyUsername: in.Username}})

	now := time.Now()
	sess := &session.Session{
		UserID:    info.ID,
		ClientID:  cl.ID,
		Scope:     info.Scope,
		Status:    session.StatusActive,
		CreatedAt: now,
		LastSeen:  now,
		ExpiresAt: now.Add(a.config.SessionTTL),
	}

	var cookie string

	if err := a.Transaction.Run(ctx, func(ctx context.Context) error {
		if err := a.sessions.Create(ctx, sess); err != nil {
			return err
		}

		var err error

		cookie, err = a.issueSessionCookie(ctx, sess, now, sess.ExpiresAt)

		return err
	}); err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	return a.buildLoginResult(ctx, sess, cl, in.ReturnTo, cookie, in.RequestTLS, in.BaseURL, in.MountPath)
}

// Refresh performs the portal's silent re-authentication.
func (a *Auth) Refresh(ctx context.Context, in RefreshRequest) (LoginResult, error) {
	if in.Token == "" {
		return LoginResult{}, NewOAuthErrorFrom(ErrLoginRequired)
	}

	claims, err := a.codec.DecodeAccess(in.Token)
	if err != nil {
		return LoginResult{}, NewOAuthErrorFrom(ErrLoginRequired)
	}

	if time.Now().Unix() >= claims.ExpiresAt {
		return LoginResult{}, NewOAuthErrorFrom(ErrLoginRequired)
	}

	sess, err := a.sessions.Get(ctx, claims.SessionID)
	if err != nil || !sess.Active() {
		return LoginResult{}, NewOAuthErrorFrom(ErrLoginRequired)
	}

	cl, err := a.clients.GetClient(ctx, sess.ClientID)
	if err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	jti, err := newJTI()
	if err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	expiresAt := time.Now().Add(a.config.SessionTTL)
	if expiresAt.After(sess.ExpiresAt) {
		expiresAt = sess.ExpiresAt
	}

	rotated, err := a.jti.Rotate(ctx, claims.TokenID, jti, sess.ID, time.Until(expiresAt))
	if err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	if !rotated {
		return LoginResult{}, NewOAuthErrorFrom(ErrLoginRequired)
	}

	_ = a.sessions.Touch(ctx, sess.ID)

	cookie, err := a.codec.Encrypt(token.AccessClaims{
		Type:      token.TypeSessionCookie,
		SessionID: sess.ID,
		TokenID:   jti,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: expiresAt.Unix(),
	})
	if err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	return a.buildLoginResult(ctx, sess, cl, in.ReturnTo, cookie, in.RequestTLS, in.BaseURL, in.MountPath)
}

// Logout is the authoritative server-side logout.
func (a *Auth) Logout(ctx context.Context, in LogoutRequest) (LogoutResult, error) {
	clearCookie := &CookieDirective{
		Name:     a.config.CookieName,
		Path:     a.Cookie.Path(in.BasePath, in.MountPath),
		MaxAge:   -1,
		Secure:   a.Cookie.Secure(in.RequestTLS),
		HTTPOnly: true,
		SameSite: a.Cookie.SameSite(),
	}

	if !a.config.LogoutInvalidatesCookie || in.Token == "" {
		return LogoutResult{ClearCookie: clearCookie}, nil
	}

	if claims, err := a.codec.DecodeAccess(in.Token); err == nil {
		if err := a.Transaction.Run(ctx, func(ctx context.Context) error {
			if err := a.sessions.Revoke(ctx, claims.SessionID); err != nil && !errors.Is(err, session.ErrNotFound) {
				return err
			}

			return a.jti.Revoke(ctx, claims.TokenID)
		}); err != nil {
			return LogoutResult{}, NewOAuthErrorFrom(err)
		}

		_ = a.fedIDTokens.Delete(ctx, claims.SessionID)
	}

	return LogoutResult{ClearCookie: clearCookie}, nil
}

// IntrospectToken validates a Bearer access token or session-cookie token
// and returns the resolved user and session.
func (a *Auth) IntrospectToken(ctx context.Context, tok string) (UserInfo, *session.Session, error) {
	if tok == "" {
		return UserInfo{}, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	claims, err := a.codec.DecodeAccess(tok)
	if err != nil {
		return UserInfo{}, nil, NewOAuthErrorFrom(err)
	}

	if time.Now().Unix() >= claims.ExpiresAt {
		return UserInfo{}, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	valid, err := a.jti.Validate(ctx, claims.TokenID, claims.SessionID)
	if err != nil {
		return UserInfo{}, nil, NewOAuthErrorFrom(err)
	}

	if !valid {
		return UserInfo{}, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	sess, err := a.sessions.Get(ctx, claims.SessionID)
	if err != nil {
		return UserInfo{}, nil, NewOAuthErrorFrom(err)
	}

	if !sess.Active() {
		return UserInfo{}, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	info, err := a.users.GetUser(ctx, sess.UserID)
	if err != nil {
		return UserInfo{}, nil, NewOAuthErrorFrom(err)
	}

	if claims.Scope != "" {
		info.Scope = claims.Scope
	}

	return info, sess, nil
}

// ListSessions returns userID's sessions, ordered by LastSeen descending.
func (a *Auth) ListSessions(ctx context.Context, userID string, filter *session.Filter, page *paginator.Paginator) ([]*session.Session, *paginator.Paginator, error) {
	lister, ok := a.sessions.(session.Lister)
	if !ok {
		return nil, nil, errors.New("session store does not support listing")
	}

	return lister.List(ctx, userID, filter, page)
}

// RevokeSession revokes sessionID after verifying it belongs to userID.
func (a *Auth) RevokeSession(ctx context.Context, userID, sessionID string) error {
	sess, err := a.sessions.Get(ctx, sessionID)
	if err != nil {
		return NewOAuthErrorFrom(err)
	}

	if sess.UserID != userID {
		return NewOAuthErrorFrom(session.ErrNotFound)
	}

	if err := a.sessions.Revoke(ctx, sessionID); err != nil {
		return NewOAuthErrorFrom(err)
	}

	_ = a.fedIDTokens.Delete(ctx, sessionID)

	return nil
}

// issueSessionCookie mints and registers a fresh session-cookie JTI for sess and returns the
// encrypted PASETO cookie value.
func (a *Auth) issueSessionCookie(ctx context.Context, sess *session.Session, issuedAt, expiresAt time.Time) (string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", NewOAuthErrorFrom(err)
	}

	if err := a.jti.Issue(ctx, jti, sess.ID, time.Until(expiresAt)); err != nil {
		return "", NewOAuthErrorFrom(err)
	}

	cookie, err := a.codec.Encrypt(token.AccessClaims{
		Type:      token.TypeSessionCookie,
		SessionID: sess.ID,
		TokenID:   jti,
		IssuedAt:  issuedAt.Unix(),
		ExpiresAt: expiresAt.Unix(),
	})
	if err != nil {
		return "", NewOAuthErrorFrom(err)
	}

	return cookie, nil
}

// buildLoginResult assembles the session-cookie directive based on client mode and configuration.
func (a *Auth) buildLoginResult(ctx context.Context, sess *session.Session, cl *client.Client, returnTo, cookie string, requestTLS bool, baseURL, mountPath string) (LoginResult, error) {
	res := LoginResult{
		Status: sess.Status,
		Cookie: &CookieDirective{
			Name:     a.config.CookieName,
			Value:    cookie,
			Path:     a.Cookie.Path(baseURL, mountPath),
			MaxAge:   int(a.config.SessionTTL.Seconds()),
			Secure:   a.Cookie.Secure(requestTLS),
			HTTPOnly: true,
			SameSite: a.Cookie.SameSite(),
		},
	}

	switch cl.ResponseMode {
	case client.ResponseModeJSON:
		at, _, err := a.issueAccessToken(ctx, sess, cl, sess.Scope, baseURL, mountPath)
		if err != nil {
			return LoginResult{}, err
		}

		res.AccessToken = at
		res.ExpiresIn = int(a.config.AccessTokenTTL.Seconds())

		if a.keys != nil && scopeContains(sess.Scope, "openid") {
			idToken, err := a.issueIDToken(ctx, sess, cl, baseURL, mountPath, "")
			if err != nil {
				return LoginResult{}, NewOAuthErrorFrom(err)
			}

			res.IDToken = idToken
		}
	case client.ResponseModeRedirect:
		res.ReturnTo = safeLocalRedirect(returnTo)
	case client.ResponseModeCookie:
		// nothing else to do
	}

	return res, nil
}

// issueIDToken issues a signed ID Token for session using client configuration.
func (a *Auth) issueIDToken(ctx context.Context, sess *session.Session, cl *client.Client, baseURL, mountPath, nonce string) (string, error) {
	keys, err := a.keys.KeySet(ctx)
	if err != nil {
		return "", err
	}

	signer, ok := keys.SignerFor(cl.IDTokenSignedResponseAlg)
	if !ok {
		return "", fmt.Errorf("client %q: no signing key for id_token algorithm %q", cl.ID, cl.IDTokenSignedResponseAlg)
	}

	now := time.Now()

	return token.SignIDToken(signer, token.IDTokenClaims{
		Issuer:    a.Issuer.URL(baseURL, mountPath),
		Subject:   sess.UserID,
		Audience:  cl.ID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(a.config.AccessTokenTTL).Unix(),
		Nonce:     nonce,
		AuthTime:  sess.CreatedAt.Unix(),
	})
}

// safeLocalRedirect validates returnTo as a local absolute path, falling back to "/".
func safeLocalRedirect(returnTo string) string {
	u, err := url.Parse(returnTo)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/") ||
		strings.HasPrefix(u.Path, "//") || strings.HasPrefix(u.Path, "/\\") {
		return "/"
	}

	return (&url.URL{Path: u.Path, RawQuery: u.RawQuery}).String()
}

// scopeContains reports whether value is one of scope's space-separated fields.
func scopeContains(scope, value string) bool {
	for scope != "" {
		tok, rest, found := strings.Cut(scope, " ")
		if tok == value {
			return true
		}

		if !found {
			return false
		}

		scope = rest
	}

	return false
}

// newJTI generates a fresh random JTI value for a session cookie or access token.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
