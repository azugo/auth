package auth

import (
	"cmp"
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

	"azugo.io/azugo"
	"azugo.io/core/http"
	"azugo.io/core/paginator"
)

// detailKeyUsername is the event detail key for username/password login flows.
const detailKeyUsername = "username"

// CookieDirective describes how to set or clear a cookie.
//
// A negative MaxAge deletes the cookie.
type CookieDirective struct {
	Name     string
	Value    string
	Path     string
	MaxAge   int
	SameSite azugo.CookieSameSite
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
	// StepToken is set while a step is pending; feed it to the step endpoints.
	StepToken string
	// Available, Selected, Interaction and Data describe the pending_mfa prompt.
	Available   []string
	Selected    string
	Interaction string
	Data        map[string]any
	// ACR and AMR are the session's satisfied authentication context and methods.
	ACR string
	AMR []string
}

// LoginRequest carries the password-grant credentials and the request-derived values.
type LoginRequest struct {
	Credentials ClientCredentials
	Username    string
	Password    string
	// ACRValues is the space-separated voluntary acr_values request.
	ACRValues string
	// Claims is the raw OIDC claims parameter; its id_token.acr entry may be essential.
	Claims    string
	ReturnTo  string
	BaseURL   string
	MountPath string
	// IP is the caller's remote address.
	IP string
}

// RefreshRequest carries the presented refresh token and the request-derived values.
type RefreshRequest struct {
	Token     string
	ReturnTo  string
	BaseURL   string
	MountPath string
}

// LogoutRequest carries the presented token and the request-derived values.
type LogoutRequest struct {
	Token     string
	BasePath  string
	MountPath string
}

// LogoutResult is returned by Logout.
type LogoutResult struct {
	ClearCookie *CookieDirective
}

// Login authenticates a password-grant request, creates an active session and returns the
// directives the caller should apply.
func (a *Auth) Login(ctx context.Context, in LoginRequest) (LoginResult, error) {
	cl, err := a.AuthenticateClient(ctx, in.Credentials, in.BaseURL, in.MountPath)
	if err != nil {
		return LoginResult{}, err
	}

	if !cl.GrantTypeAllowed(client.GrantTypePassword) || !cl.AuthMethodAllowed(client.AuthMethodPassword) {
		return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeUnauthorizedClient, "client is not allowed to use the password grant")
	}

	// Throttle keys combine the stable identity with the IP so neither a single account nor
	// a single source can be brute-forced.
	keys := throttleKeys("", in.IP)
	if in.Username != "" {
		keys = throttleKeys("pwd:"+in.Username, in.IP)
	}

	if err := a.checkThrottle(ctx, keys, cl.ID, in.IP); err != nil {
		return LoginResult{}, err
	}

	info, err := a.users.Authenticate(ctx, in.Username, in.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			a.failThrottle(ctx, keys)
		} else {
			a.refundThrottle(ctx, keys)
		}

		a.emit(ctx, event.Event{Type: event.TypeLoginFailure, ClientID: cl.ID, IP: in.IP, Detail: map[string]any{detailKeyUsername: in.Username}})

		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	if in.Username != "" {
		a.passThrottle(ctx, keys)
	} else {
		a.refundThrottle(ctx, keys)
	}

	a.emit(ctx, event.Event{Type: event.TypeLoginSuccess, UserID: info.ID, ClientID: cl.ID, IP: in.IP, Detail: map[string]any{detailKeyUsername: in.Username}})

	sess := &session.Session{
		UserID:   info.ID,
		ClientID: cl.ID,
		Scope:    clientScope(cl, info.Scope),
		AMR:      mergeAMR([]string{amrPassword}, info.AMR),
	}

	return a.startSession(ctx, sess, cl, parseACRRequest(in.ACRValues, in.Claims), in.ReturnTo, in.BaseURL, in.MountPath)
}

// Refresh performs the portal's silent re-authentication.
func (a *Auth) Refresh(ctx context.Context, in RefreshRequest) (LoginResult, error) {
	if in.Token == "" {
		return LoginResult{}, NewOAuthErrorFrom(ErrLoginRequired)
	}

	claims, err := a.codec.DecodeSessionCookie(in.Token)
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

	return a.buildLoginResult(ctx, sess, cl, in.ReturnTo, cookie, in.BaseURL, in.MountPath)
}

// Logout is the authoritative server-side logout.
func (a *Auth) Logout(ctx context.Context, in LogoutRequest) (LogoutResult, error) {
	clearCookie := &CookieDirective{
		Name:     a.config.CookieName,
		Path:     a.Cookie.Path(in.BasePath, in.MountPath),
		MaxAge:   -1,
		SameSite: a.Cookie.SameSite(),
	}

	if !a.config.LogoutInvalidatesCookie || in.Token == "" {
		return LogoutResult{ClearCookie: clearCookie}, nil
	}

	claims, err := a.codec.DecodeAccess(in.Token)
	if err != nil {
		return LogoutResult{ClearCookie: clearCookie}, nil //nolint:nilerr
	}

	live, err := a.live(ctx, claims)
	if err != nil {
		return LogoutResult{}, NewOAuthErrorFrom(err)
	}

	if !live {
		return LogoutResult{ClearCookie: clearCookie}, nil
	}

	sess, err := a.sessions.Get(ctx, claims.SessionID)

	switch {
	case errors.Is(err, session.ErrNotFound), err == nil && !firstParty(claims, sess):
		// Missing session needs no revocation
		return LogoutResult{ClearCookie: clearCookie}, nil
	case err != nil:
		return LogoutResult{}, NewOAuthErrorFrom(err)
	}

	if err := a.Transaction.Run(ctx, func(ctx context.Context) error {
		if err := a.sessions.Revoke(ctx, sess.ID); err != nil && !errors.Is(err, session.ErrNotFound) {
			return err
		}

		return a.jti.Revoke(ctx, claims.TokenID)
	}); err != nil {
		return LogoutResult{}, NewOAuthErrorFrom(err)
	}

	_ = deleteSynced(ctx, a.fedIDTokens, sess.ID)

	return LogoutResult{ClearCookie: clearCookie}, nil
}

// IntrospectToken validates a Bearer access token or session-cookie token
// and returns the resolved user and session.
func (a *Auth) IntrospectToken(ctx context.Context, tok string) (UserInfo, *session.Session, error) {
	info, sess, _, err := a.introspect(ctx, tok)

	return info, sess, err
}

// IntrospectFirstParty validates a token like IntrospectToken but additionally requires it to
// be the session's own credential.
func (a *Auth) IntrospectFirstParty(ctx context.Context, tok string) (UserInfo, *session.Session, error) {
	info, sess, claims, err := a.introspect(ctx, tok)
	if err != nil {
		return UserInfo{}, nil, err
	}

	if !firstParty(claims, sess) {
		return UserInfo{}, nil, NewOAuthErrorFrom(ErrFirstPartyRequired)
	}

	return info, sess, nil
}

func (a *Auth) introspect(ctx context.Context, tok string) (UserInfo, *session.Session, *token.AccessClaims, error) {
	if tok == "" {
		return UserInfo{}, nil, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	claims, err := a.codec.DecodeAccess(tok)
	if err != nil {
		return UserInfo{}, nil, nil, NewOAuthErrorFrom(err)
	}

	if time.Now().Unix() >= claims.ExpiresAt {
		return UserInfo{}, nil, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	valid, err := a.jti.Validate(ctx, claims.TokenID, claims.SessionID)
	if err != nil {
		return UserInfo{}, nil, nil, NewOAuthErrorFrom(err)
	}

	if !valid {
		return UserInfo{}, nil, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	sess, err := a.sessions.Get(ctx, claims.SessionID)
	if err != nil {
		return UserInfo{}, nil, nil, NewOAuthErrorFrom(err)
	}

	if !sess.Active() {
		return UserInfo{}, nil, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	info, err := a.users.GetUser(ctx, sess.UserID)
	if err != nil {
		return UserInfo{}, nil, nil, NewOAuthErrorFrom(err)
	}

	info.Scope = allowedScope(info.Scope, strings.FieldsSeq(sess.Scope))
	if claims.Scope != "" {
		info.Scope = claims.Scope
	}

	info.ACR = sess.ACR
	info.AMR = sess.AMR
	info.ClientID = cmp.Or(claims.ClientID, sess.ClientID)

	return info, sess, claims, nil
}

// live reports whether claims still name a usable and not expired credential.
func (a *Auth) live(ctx context.Context, claims *token.AccessClaims) (bool, error) {
	if time.Now().Unix() >= claims.ExpiresAt {
		return false, nil
	}

	return a.jti.Validate(ctx, claims.TokenID, claims.SessionID)
}

// firstParty reports whether claims are session's own credential.
func firstParty(claims *token.AccessClaims, sess *session.Session) bool {
	return claims.Type != token.TypeAccessToken || claims.ClientID == sess.ClientID
}

// UserInfoClaims resolves the OIDC UserInfo claims a token's granted scope permits.
func (a *Auth) UserInfoClaims(ctx context.Context, tok string) (UserInfo, error) {
	info, _, err := a.IntrospectToken(ctx, tok)
	if err != nil {
		return UserInfo{}, err
	}

	if !scopeContains(info.Scope, ScopeOpenID) {
		return UserInfo{}, NewOAuthError(http.StatusForbidden, ErrCodeInsufficientScope, "openid scope is required")
	}

	if !scopeContains(info.Scope, ScopeProfile) {
		info.Name = ""
	}

	if !scopeContains(info.Scope, ScopeEmail) {
		info.Email = ""
	}

	return info, nil
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

	_ = deleteSynced(ctx, a.fedIDTokens, sessionID)

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

// cookieDirective builds the session-cookie directive for value.
func (a *Auth) cookieDirective(value string, maxAge time.Duration, baseURL, mountPath string) *CookieDirective {
	return &CookieDirective{
		Name:     a.config.CookieName,
		Value:    value,
		Path:     a.Cookie.Path(baseURL, mountPath),
		MaxAge:   int(maxAge.Seconds()),
		SameSite: a.Cookie.SameSite(),
	}
}

// buildLoginResult assembles the session-cookie directive based on client mode and configuration.
func (a *Auth) buildLoginResult(ctx context.Context, sess *session.Session, cl *client.Client, returnTo, cookie string, baseURL, mountPath string) (LoginResult, error) {
	res := LoginResult{
		Status: sess.Status,
		Cookie: a.cookieDirective(cookie, a.config.SessionTTL, baseURL, mountPath),
		ACR:    sess.ACR,
		AMR:    sess.AMR,
	}

	switch cl.ResponseMode {
	case client.ResponseModeJSON:
		at, _, err := a.issueAccessToken(ctx, sess, cl, sess.Scope, baseURL, mountPath)
		if err != nil {
			return LoginResult{}, err
		}

		res.AccessToken = at
		res.ExpiresIn = int(a.config.AccessTokenTTL.Seconds())

		if a.keys != nil && scopeContains(sess.Scope, ScopeOpenID) {
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
		ACR:       sess.ACR,
		AMR:       sess.AMR,
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

// newJTI generates a fresh random JTI value for a session cookie or access token.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
