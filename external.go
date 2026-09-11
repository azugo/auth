package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"time"

	"azugo.io/auth/contract"
	"azugo.io/auth/event"
	"azugo.io/auth/provider"
	"azugo.io/auth/session"

	"azugo.io/core/cache"
	"azugo.io/core/http"
	"azugo.io/core/paginator"
	"go.uber.org/zap"
)

// Event detail map keys used across external identity flows.
const (
	detailKeyProvider = "provider"
	detailKeySubject  = "subject"
)

// External state entry kinds.
const (
	extKindLogin         = "login"
	extKindLink          = "link"
	extKindLogout        = "logout"
	extKindLoginFinalize = "login_finalize"
)

// externalState is one stashed IdP round-trip, keyed by the opaque state value.
type externalState struct {
	Kind         string
	Provider     string
	ClientID     string
	Nonce        string
	CodeVerifier string
	ReturnTo     string
	// UserID is the linking user (kind link).
	UserID string
	// Info, IDToken carry the deferred session identity (kind login_finalize).
	Info    UserInfo
	IDToken string
	// RedirectURI is the validated post_logout_redirect_uri (kind logout).
	RedirectURI string
}

// ExternalLoginRequest starts an external IdP login round-trip.
type ExternalLoginRequest struct {
	Provider string
	ClientID string
	ReturnTo string
}

// ExternalLinkRequest starts an account-linking round-trip for the presented session.
type ExternalLinkRequest struct {
	Provider string
	Token    string
	ReturnTo string
}

// RedirectResult carries the IdP redirect the caller should perform.
type RedirectResult struct {
	Redirect string
}

// BeginExternalLogin resolves the provider, stashes the round-trip state and returns the IdP
// authorization URL.
func (a *Auth) BeginExternalLogin(ctx context.Context, in ExternalLoginRequest) (RedirectResult, error) {
	p, _, err := a.providers.Get(ctx, in.Provider)
	if err != nil {
		return RedirectResult{}, NewOAuthErrorFrom(err)
	}

	cl, err := a.clients.GetClient(ctx, in.ClientID)
	if err != nil {
		return RedirectResult{}, NewOAuthErrorFrom(err)
	}

	if !cl.AuthMethodAllowed(in.Provider) {
		return RedirectResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeUnauthorizedClient, "client is not allowed to use this authentication method")
	}

	return a.beginExternal(ctx, p, externalState{
		Kind:     extKindLogin,
		Provider: in.Provider,
		ClientID: cl.ID,
		ReturnTo: in.ReturnTo,
	})
}

// BeginExternalLink starts the linking ceremony: the same IdP round-trip as login bound to the
// authenticated caller.
func (a *Auth) BeginExternalLink(ctx context.Context, in ExternalLinkRequest) (RedirectResult, error) {
	if a.identities == nil {
		return RedirectResult{}, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "account linking is not enabled")
	}

	info, sess, err := a.IntrospectToken(ctx, in.Token)
	if err != nil {
		return RedirectResult{}, err
	}

	p, _, err := a.providers.Get(ctx, in.Provider)
	if err != nil {
		return RedirectResult{}, NewOAuthErrorFrom(err)
	}

	return a.beginExternal(ctx, p, externalState{
		Kind:     extKindLink,
		Provider: in.Provider,
		ClientID: sess.ClientID,
		ReturnTo: in.ReturnTo,
		UserID:   info.ID,
	})
}

func (a *Auth) beginExternal(ctx context.Context, p provider.Provider, st externalState) (RedirectResult, error) {
	state, err := newJTI()
	if err != nil {
		return RedirectResult{}, NewOAuthErrorFrom(err)
	}

	nonce, err := newJTI()
	if err != nil {
		return RedirectResult{}, NewOAuthErrorFrom(err)
	}

	// A 32-byte verifier encodes to the RFC 7636 minimum of 43 unreserved characters.
	vb := make([]byte, 32)
	if _, err := rand.Read(vb); err != nil {
		return RedirectResult{}, NewOAuthErrorFrom(err)
	}

	verifier := base64.RawURLEncoding.EncodeToString(vb)

	st.Nonce = nonce
	st.CodeVerifier = verifier

	if err := a.extstate.Set(ctx, state, st, cache.TTL[externalState](a.config.ExternalStateTTL)); err != nil {
		return RedirectResult{}, NewOAuthErrorFrom(err)
	}

	sum := sha256.Sum256([]byte(verifier))

	uri, err := p.AuthURL(ctx, state, nonce, base64.RawURLEncoding.EncodeToString(sum[:]))
	if err != nil {
		return RedirectResult{}, NewOAuthErrorFrom(err)
	}

	return RedirectResult{Redirect: uri}, nil
}

// ExternalCallbackRequest carries the IdP redirect back to /external/{provider}/callback.
type ExternalCallbackRequest struct {
	Provider string
	State    string
	Code     string
	// Error and ErrorDescription pass through an upstream IdP error response.
	Error            string
	ErrorDescription string
	RequestTLS       bool
	BaseURL          string
	MountPath        string
	IP               string
}

// ExternalCallbackResult is returned by ExternalCallback.
type ExternalCallbackResult struct {
	// Login is set when a session was finalized immediately.
	Login *LoginResult
	// Redirect is the off-origin IdP end-session hop (LogoutAfterAuth).
	Redirect string
	// ReturnTo is the link-ceremony return target as a local path.
	ReturnTo string
	// Link is the resulting identity link (link ceremony only).
	Link *provider.IdentityLink
}

// ExternalCallback validates the IdP redirect, exchanges the code and branches on the stashed
// entry kind.
func (a *Auth) ExternalCallback(ctx context.Context, in ExternalCallbackRequest) (ExternalCallbackResult, error) {
	st, err := a.consumeExternalState(ctx, in.State, in.Provider, extKindLogin, extKindLink)
	if err != nil {
		return ExternalCallbackResult{}, err
	}

	if in.Error != "" {
		return ExternalCallbackResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeAccessDenied, "external provider error: "+in.Error)
	}

	p, cfg, err := a.providers.Get(ctx, in.Provider)
	if err != nil {
		return ExternalCallbackResult{}, NewOAuthErrorFrom(err)
	}

	tokens, err := p.Exchange(ctx, in.Code, st.CodeVerifier, st.Nonce)
	if err != nil {
		a.emit(ctx, event.Event{Type: event.TypeLoginFailure, ClientID: st.ClientID, IP: in.IP, Detail: map[string]any{detailKeyProvider: in.Provider}})

		return ExternalCallbackResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "external token exchange failed")
	}

	info, err := a.mapExternalClaims(ctx, cfg, in.Provider, tokens.RawClaims)
	if err != nil {
		a.emit(ctx, event.Event{Type: event.TypeLoginFailure, ClientID: st.ClientID, IP: in.IP, Detail: map[string]any{detailKeyProvider: in.Provider}})

		return ExternalCallbackResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "external identity rejected")
	}

	if st.Kind == extKindLink {
		link, err := a.linkExternalIdentity(ctx, st.UserID, in.Provider, info, in.IP)
		if err != nil {
			return ExternalCallbackResult{}, err
		}

		res := ExternalCallbackResult{Link: link}
		if st.ReturnTo != "" {
			res.ReturnTo = safeLocalRedirect(st.ReturnTo)
		}

		return res, nil
	}

	info, err = a.resolveExternalUser(ctx, in.Provider, info)
	if err != nil {
		return ExternalCallbackResult{}, NewOAuthErrorFrom(err)
	}

	st.Info = info
	st.IDToken = tokens.IDToken

	// Defer session creation to the IdP logout callback
	if cfg.LogoutAfterAuth {
		return a.deferExternalLogin(ctx, p, *st, in.BaseURL, in.MountPath)
	}

	login, err := a.finalizeExternalLogin(ctx, *st, in.RequestTLS, in.BaseURL, in.MountPath, in.IP)
	if err != nil {
		return ExternalCallbackResult{}, err
	}

	return ExternalCallbackResult{Login: &login}, nil
}

func (a *Auth) deferExternalLogin(ctx context.Context, p provider.Provider, st externalState, baseURL, mountPath string) (ExternalCallbackResult, error) {
	lo, ok := p.(provider.Logouter)
	if !ok {
		return ExternalCallbackResult{}, NewOAuthError(http.StatusInternalServerError, ErrCodeServerError, "provider does not support RP-initiated logout")
	}

	state, err := newJTI()
	if err != nil {
		return ExternalCallbackResult{}, NewOAuthErrorFrom(err)
	}

	idToken := st.IDToken
	st.Kind = extKindLoginFinalize

	if err := a.extstate.Set(ctx, state, st, cache.TTL[externalState](a.config.ExternalStateTTL)); err != nil {
		return ExternalCallbackResult{}, NewOAuthErrorFrom(err)
	}

	uri, err := lo.LogoutURL(ctx, idToken, state, a.externalLogoutCallbackURL(baseURL, mountPath, st.Provider))
	if err != nil {
		return ExternalCallbackResult{}, NewOAuthErrorFrom(err)
	}

	return ExternalCallbackResult{Redirect: uri}, nil
}

// ExternalLogoutCallbackRequest carries the IdP redirect back from its end-session endpoint.
type ExternalLogoutCallbackRequest struct {
	Provider   string
	State      string
	RequestTLS bool
	BaseURL    string
	MountPath  string
	IP         string
}

// ExternalLogoutCallbackResult is returned by ExternalLogoutCallback.
type ExternalLogoutCallbackResult struct {
	// Login is set when a deferred external login was finalized.
	Login *LoginResult
	// Redirect is the validated post-logout target (logout kind), which may be off-origin.
	Redirect string
}

// ExternalLogoutCallback validates the returned state and either finalizes a deferred external
// login or completes a federated logout.
func (a *Auth) ExternalLogoutCallback(ctx context.Context, in ExternalLogoutCallbackRequest) (ExternalLogoutCallbackResult, error) {
	st, err := a.consumeExternalState(ctx, in.State, in.Provider, extKindLoginFinalize, extKindLogout)
	if err != nil {
		return ExternalLogoutCallbackResult{}, err
	}

	if st.Kind == extKindLogout {
		return ExternalLogoutCallbackResult{Redirect: st.RedirectURI}, nil
	}

	login, err := a.finalizeExternalLogin(ctx, *st, in.RequestTLS, in.BaseURL, in.MountPath, in.IP)
	if err != nil {
		return ExternalLogoutCallbackResult{}, err
	}

	return ExternalLogoutCallbackResult{Login: &login}, nil
}

func (a *Auth) consumeExternalState(ctx context.Context, state, providerName string, kinds ...string) (*externalState, error) {
	if state == "" {
		return nil, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "missing state")
	}

	st, err := a.extstate.Pop(ctx, state)
	if err != nil || st.Provider != providerName {
		return nil, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "invalid state")
	}

	for _, kind := range kinds {
		if st.Kind == kind {
			return &st, nil
		}
	}

	return nil, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "invalid state")
}

func (a *Auth) mapExternalClaims(ctx context.Context, cfg *contract.ExternalProviderConfig, providerName string, raw map[string]any) (UserInfo, error) {
	mapper := cfg.ClaimMapper

	if mapper == nil {
		mapper = a.providerClaims
	}

	if mapper == nil {
		var err error
		if mapper, err = provider.DefaultClaimMapper(cfg.Driver); err != nil {
			return UserInfo{}, err
		}
	}

	return mapper.MapClaims(ctx, providerName, raw)
}

func (a *Auth) resolveExternalUser(ctx context.Context, providerName string, info UserInfo) (UserInfo, error) {
	subject := info.ID

	if a.identities != nil {
		link, err := a.identities.Lookup(ctx, providerName, subject)

		switch {
		case err == nil:
			local, err := a.users.GetUser(ctx, link.UserID)
			if err != nil {
				return UserInfo{}, err
			}

			// Touch LastUsedAt via the same-user upsert
			_ = a.identities.Link(ctx, link)

			local.AMR = mergeAMR(local.AMR, info.AMR)

			return local, nil
		case !errors.Is(err, provider.ErrLinkNotFound):
			return UserInfo{}, err
		}
	}

	if resolver, ok := a.users.(ExternalUserProvider); ok {
		resolved, err := resolver.FindOrCreateUser(ctx, providerName, info)
		if err != nil {
			return UserInfo{}, err
		}

		resolved.AMR = mergeAMR(resolved.AMR, info.AMR)
		info = resolved
	}

	if a.identities != nil {
		if err := a.identities.Link(ctx, &provider.IdentityLink{
			UserID:   info.ID,
			Provider: providerName,
			Subject:  subject,
			Email:    info.Email,
			LinkedAt: time.Now(),
		}); err != nil {
			return UserInfo{}, err
		}

		a.emit(ctx, event.Event{Type: event.TypeIdentityLinked, UserID: info.ID, Detail: map[string]any{detailKeyProvider: providerName, detailKeySubject: subject}})
	}

	return info, nil
}

func (a *Auth) linkExternalIdentity(ctx context.Context, userID, providerName string, info UserInfo, ip string) (*provider.IdentityLink, error) {
	link := &provider.IdentityLink{
		UserID:   userID,
		Provider: providerName,
		Subject:  info.ID,
		Email:    info.Email,
		LinkedAt: time.Now(),
	}

	existing, err := a.identities.Lookup(ctx, providerName, info.ID)

	switch {
	case errors.Is(err, provider.ErrLinkNotFound):
		// Conflict-free insert below.
	case err != nil:
		return nil, NewOAuthErrorFrom(err)
	case existing.UserID == userID:
		return existing, nil
	default:
		allowed := false
		if a.relink != nil {
			if allowed, err = a.relink.AllowRelink(ctx, existing, userID); err != nil {
				return nil, NewOAuthErrorFrom(err)
			}
		}

		if !allowed {
			return nil, NewOAuthErrorFrom(provider.ErrIdentityLinked)
		}

		if err := a.Transaction.Run(ctx, func(ctx context.Context) error {
			if err := a.identities.Unlink(ctx, existing.UserID, existing.ID); err != nil {
				return err
			}

			return a.identities.Link(ctx, link)
		}); err != nil {
			return nil, NewOAuthErrorFrom(err)
		}

		a.emit(ctx, event.Event{Type: event.TypeIdentityUnlinked, UserID: existing.UserID, IP: ip, Detail: map[string]any{detailKeyProvider: providerName, detailKeySubject: info.ID}})
		a.emit(ctx, event.Event{Type: event.TypeIdentityLinked, UserID: userID, IP: ip, Detail: map[string]any{detailKeyProvider: providerName, detailKeySubject: info.ID}})

		return link, nil
	}

	if err := a.identities.Link(ctx, link); err != nil {
		return nil, NewOAuthErrorFrom(err)
	}

	a.emit(ctx, event.Event{Type: event.TypeIdentityLinked, UserID: userID, IP: ip, Detail: map[string]any{detailKeyProvider: providerName, detailKeySubject: info.ID}})

	return link, nil
}

func (a *Auth) finalizeExternalLogin(ctx context.Context, st externalState, requestTLS bool, baseURL, mountPath, ip string) (LoginResult, error) {
	cl, err := a.clients.GetClient(ctx, st.ClientID)
	if err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	info := st.Info
	now := time.Now()
	sess := &session.Session{
		UserID:       info.ID,
		ClientID:     cl.ID,
		Scope:        info.Scope,
		Status:       session.StatusActive,
		AuthProvider: st.Provider,
		AMR:          info.AMR,
		CreatedAt:    now,
		LastSeen:     now,
		ExpiresAt:    now.Add(a.config.SessionTTL),
	}

	var cookie string

	if err := a.Transaction.Run(ctx, func(ctx context.Context) error {
		if err := a.sessions.Create(ctx, sess); err != nil {
			return err
		}

		cookie, err = a.issueSessionCookie(ctx, sess, now, sess.ExpiresAt)

		return err
	}); err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	if st.IDToken != "" {
		if err := a.fedIDTokens.Set(ctx, sess.ID, st.IDToken, cache.TTL[string](a.config.SessionTTL)); err != nil {
			// The login still succeeds; federated logout for this session runs without id_token_hint.
			a.Log(ctx).Warn("failed to cache IdP id_token for federated logout", zap.String("session.id", sess.ID), zap.Error(err))
		}
	}

	a.emit(ctx, event.Event{Type: event.TypeLoginSuccess, UserID: info.ID, ClientID: cl.ID, IP: ip, Detail: map[string]any{detailKeyProvider: st.Provider}})

	return a.buildLoginResult(ctx, sess, cl, st.ReturnTo, cookie, requestTLS, baseURL, mountPath)
}

// BrowserLogoutRequest carries GET /logout: the redirect-based browser logout.
type BrowserLogoutRequest struct {
	Token                 string
	PostLogoutRedirectURI string
	// Federated forces the IdP end-session hop even when Client.FederatedLogout is unset.
	Federated  bool
	RequestTLS bool
	BaseURL    string
	MountPath  string
	IP         string
}

// BrowserLogoutResult is browser logout result.
type BrowserLogoutResult struct {
	ClearCookie *CookieDirective
	// Redirect is the IdP end-session hop or the validated post-logout target.
	Redirect string
}

// BrowserLogout applies the authoritative local logout, then redirects either to the IdP
// end-session endpoint or straight to the validated post-logout target.
func (a *Auth) BrowserLogout(ctx context.Context, in BrowserLogoutRequest) (BrowserLogoutResult, error) {
	result := BrowserLogoutResult{
		ClearCookie: &CookieDirective{
			Name:     a.config.CookieName,
			Path:     a.Cookie.Path(in.BaseURL, in.MountPath),
			MaxAge:   -1,
			Secure:   a.Cookie.Secure(in.RequestTLS),
			HTTPOnly: true,
			SameSite: a.Cookie.SameSite(),
		},
		Redirect: "/",
	}

	if in.Token == "" {
		return result, nil
	}

	// Logout must succeed locally
	claims, err := a.codec.DecodeAccess(in.Token)
	if err != nil {
		return result, nil //nolint:nilerr
	}

	sess, err := a.sessions.Get(ctx, claims.SessionID)
	if err != nil {
		return result, nil //nolint:nilerr
	}

	if a.config.LogoutInvalidatesCookie {
		if err := a.Transaction.Run(ctx, func(ctx context.Context) error {
			if err := a.sessions.Revoke(ctx, sess.ID); err != nil && !errors.Is(err, session.ErrNotFound) {
				return err
			}

			return a.jti.Revoke(ctx, claims.TokenID)
		}); err != nil {
			return BrowserLogoutResult{}, NewOAuthErrorFrom(err)
		}
	}

	cl, err := a.clients.GetClient(ctx, sess.ClientID)
	if err != nil {
		return result, nil //nolint:nilerr
	}

	if in.PostLogoutRedirectURI != "" && slices.Contains(cl.PostLogoutRedirectURIs, in.PostLogoutRedirectURI) {
		result.Redirect = in.PostLogoutRedirectURI
	}

	if sess.AuthProvider == "" || (!cl.FederatedLogout && !in.Federated) {
		return result, nil
	}

	p, _, err := a.providers.Get(ctx, sess.AuthProvider)
	if err != nil {
		return result, nil //nolint:nilerr
	}

	lo, ok := p.(provider.Logouter)
	if !ok {
		return result, nil
	}

	idToken, err := a.fedIDTokens.Pop(ctx, sess.ID)
	if err != nil {
		idToken = ""
	}

	state, err := newJTI()
	if err != nil {
		return BrowserLogoutResult{}, NewOAuthErrorFrom(err)
	}

	if err := a.extstate.Set(ctx, state, externalState{
		Kind:        extKindLogout,
		Provider:    sess.AuthProvider,
		RedirectURI: result.Redirect,
	}, cache.TTL[externalState](a.config.ExternalStateTTL)); err != nil {
		return BrowserLogoutResult{}, NewOAuthErrorFrom(err)
	}

	uri, err := lo.LogoutURL(ctx, idToken, state, a.externalLogoutCallbackURL(in.BaseURL, in.MountPath, sess.AuthProvider))
	if err != nil {
		return result, nil //nolint:nilerr
	}

	result.Redirect = uri

	return result, nil
}

func (a *Auth) externalLogoutCallbackURL(baseURL, mountPath, providerName string) string {
	return a.Issuer.URL(baseURL, mountPath) + "/external/" + providerName + "/logout/callback"
}

// ListIdentities returns userID's linked external identities.
func (a *Auth) ListIdentities(ctx context.Context, userID, providerName string, page *paginator.Paginator) ([]*provider.IdentityLink, *paginator.Paginator, error) {
	if a.identities == nil {
		return nil, nil, errors.New("identity store is not configured")
	}

	return a.identities.List(ctx, userID, providerName, page)
}

// UnlinkIdentity removes one of userID's own identity links.
func (a *Auth) UnlinkIdentity(ctx context.Context, userID, linkID string) error {
	if a.identities == nil {
		return errors.New("identity store is not configured")
	}

	if err := a.identities.Unlink(ctx, userID, linkID); err != nil {
		return NewOAuthErrorFrom(err)
	}

	a.emit(ctx, event.Event{Type: event.TypeIdentityUnlinked, UserID: userID, Detail: map[string]any{"link_id": linkID}})

	return nil
}

func mergeAMR(local, external []string) []string {
	for _, v := range external {
		if !slices.Contains(local, v) {
			local = append(local, v)
		}
	}

	return local
}
