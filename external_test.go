package auth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/provider"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
)

// fakeExtProvider simulates an external IdP: AuthURL/LogoutURL are recognisable literals and
// Exchange succeeds for any code, echoing the identity claims configured on the driver entry.
type fakeExtProvider struct {
	cfg *contract.ExternalProviderConfig
}

func (p *fakeExtProvider) AuthURL(_ context.Context, state, nonce, codeChallenge string) (string, error) {
	q := url.Values{"state": {state}, "nonce": {nonce}, "code_challenge": {codeChallenge}}

	return "https://idp.example/authorize?" + q.Encode(), nil
}

func (p *fakeExtProvider) Exchange(_ context.Context, code, codeVerifier, _ string) (*provider.Tokens, error) {
	if code == "" || codeVerifier == "" {
		return nil, errors.New("missing code or verifier")
	}

	sub := p.cfg.Config["sub"]
	if sub == "" {
		sub = "ext-1"
	}

	return &provider.Tokens{
		IDToken: "idt-" + code,
		RawClaims: map[string]any{
			"sub": sub, "name": "Ext Alice", "email": "ext@example.com", "scp": "openid profile",
		},
	}, nil
}

type fakeExtLogoutProvider struct {
	fakeExtProvider
}

func (p *fakeExtLogoutProvider) LogoutURL(_ context.Context, idTokenHint, state, postLogoutRedirectURI string) (string, error) {
	q := url.Values{"state": {state}, "post_logout_redirect_uri": {postLogoutRedirectURI}}
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}

	return "https://idp.example/logout?" + q.Encode(), nil
}

type fakeExtDriver struct {
	logout bool
}

func (d fakeExtDriver) Open(cfg *contract.ExternalProviderConfig) (provider.Provider, error) {
	if d.logout {
		return &fakeExtLogoutProvider{fakeExtProvider{cfg: cfg}}, nil
	}

	return &fakeExtProvider{cfg: cfg}, nil
}

func (fakeExtDriver) DefaultClaimMapper() provider.ClaimMapper {
	return provider.ClaimMapperFunc(provider.MapStandardClaims)
}

func init() {
	provider.Register("fake", fakeExtDriver{})
	provider.Register("fakelogout", fakeExtDriver{logout: true})
}

// extTestUsers resolves external identities to local users via FindOrCreateUser.
type extTestUsers struct {
	fakeUsers
}

func (f extTestUsers) FindOrCreateUser(_ context.Context, _ string, info UserInfo) (UserInfo, error) {
	return UserInfo{ID: "local-" + info.ID, Name: info.Name, Email: info.Email, Scope: info.Scope}, nil
}

func (f extTestUsers) GetUser(ctx context.Context, id string) (UserInfo, error) {
	if strings.HasPrefix(id, "local-") {
		return UserInfo{ID: id, Name: "Ext Alice", Email: "ext@example.com", Scope: "openid profile"}, nil
	}

	return f.fakeUsers.GetUser(ctx, id)
}

func newExternalTestAuth(t *testing.T, providers []contract.ExternalProviderConfig, users UserProvider, cl *client.Client, opts ...Option) *Auth {
	t.Helper()

	cfg := validConfig()
	cfg.LogoutInvalidatesCookie = true
	cfg.Providers = providers

	if users == nil {
		users = extTestUsers{fakeUsers{
			users:     map[string]UserInfo{"alice": {ID: "u1", Name: "Alice", Scope: "openid"}, "carol": {ID: "u2", Name: "Carol", Scope: "openid"}},
			passwords: map[string]string{"alice": "secret123", "carol": "secret123"},
		}}
	}

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(cl), opts...)
	qt.Assert(t, qt.IsNil(err))

	return a
}

// beginAndExtractState starts an external login and returns the state handed to the IdP.
func beginAndExtractState(t *testing.T, a *Auth, providerName, clientID, returnTo string) (state, binding string) {
	t.Helper()

	res, err := a.BeginExternalLogin(context.Background(), ExternalLoginRequest{Provider: providerName, ClientID: clientID, ReturnTo: returnTo})
	qt.Assert(t, qt.IsNil(err))

	u, err := url.Parse(res.Redirect)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(u.Query().Get("code_challenge") != ""))
	qt.Check(t, qt.IsTrue(u.Query().Get("nonce") != ""))

	state = u.Query().Get("state")
	qt.Assert(t, qt.IsTrue(state != ""))
	qt.Assert(t, qt.IsNotNil(res.Cookie))

	return state, res.Cookie.Value
}

func extPortalClient() *client.Client {
	return &client.Client{ID: "portal", ResponseMode: client.ResponseModeRedirect}
}

func extProviderEntry(name, driver string) contract.ExternalProviderConfig {
	return contract.ExternalProviderConfig{
		Name: name, Driver: driver, ClientID: "app-client",
		RedirectURL: "https://app.example/auth/external/" + name + "/callback",
	}
}

func TestExternalLoginFlow(t *testing.T) {
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, extPortalClient())

	state, binding := beginAndExtractState(t, a, "corp", "portal", "/dashboard")

	res, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{
		Provider: "corp", State: state, Binding: binding, Code: "code-1", BaseURL: "https://app.example",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(res.Login))

	qt.Check(t, qt.Equals(res.Login.Status, session.StatusActive))
	qt.Check(t, qt.Equals(res.Login.ReturnTo, "/dashboard"))
	qt.Assert(t, qt.IsNotNil(res.Login.Cookie))

	// The session carries the resolved local user and the originating provider.
	info, sess, err := a.IntrospectToken(context.Background(), res.Login.Cookie.Value)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.ID, "local-ext-1"))
	qt.Check(t, qt.Equals(sess.AuthProvider, "corp"))
}

func TestExternalLoginUnknownProviderAndDisallowedMethod(t *testing.T) {
	cl := extPortalClient()
	cl.AllowedAuthMethods = []string{client.AuthMethodPassword}
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, cl)

	_, err := a.BeginExternalLogin(context.Background(), ExternalLoginRequest{Provider: "nope", ClientID: "portal"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	_, err = a.BeginExternalLogin(context.Background(), ExternalLoginRequest{Provider: "corp", ClientID: "portal"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnauthorizedClient))
}

func TestExternalCallbackStateValidation(t *testing.T) {
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, extPortalClient())

	// Unknown state.
	_, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: "bogus", Code: "c"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	// Provider mismatch consumes nothing usable.
	state, binding := beginAndExtractState(t, a, "corp", "portal", "")
	_, err = a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "other", State: state, Binding: binding, Code: "c"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	// Replay: a consumed state cannot be used again.
	state, binding = beginAndExtractState(t, a, "corp", "portal", "")

	_, err = a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: binding, Code: "c"})
	qt.Assert(t, qt.IsNil(err))

	_, err = a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: binding, Code: "c"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

func TestExternalCallbackUpstreamError(t *testing.T) {
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, extPortalClient())

	state, binding := beginAndExtractState(t, a, "corp", "portal", "")

	_, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: binding, Error: "access_denied"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeAccessDenied))
}

func TestExternalLoginAutoLinksAndResolvesViaIdentityStore(t *testing.T) {
	store := provider.NewMemoryIdentityStore()
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, extPortalClient(), IdentityStore(store))

	state, binding := beginAndExtractState(t, a, "corp", "portal", "")

	res, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: binding, Code: "c1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(res.Login))

	// First login auto-linked the resolved user.
	link, err := store.Lookup(context.Background(), "corp", "ext-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(link.UserID, "local-ext-1"))

	// Second login resolves through the link (and touches LastUsedAt).
	state, binding = beginAndExtractState(t, a, "corp", "portal", "")

	res, err = a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: binding, Code: "c2"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(res.Login))

	link, err = store.Lookup(context.Background(), "corp", "ext-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNotNil(link.LastUsedAt))

	links, _, err := a.ListIdentities(context.Background(), "local-ext-1", "", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(links, 1))
}

func TestExternalLinkCeremonyAndConflict(t *testing.T) {
	store := provider.NewMemoryIdentityStore()
	cl := extPortalClient()
	cl.GrantTypes = []string{client.GrantTypePassword}
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, cl, IdentityStore(store))

	login, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "portal"}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	res, err := a.BeginExternalLink(context.Background(), ExternalLinkRequest{Provider: "corp", Token: login.Cookie.Value, ReturnTo: "/profile"})
	qt.Assert(t, qt.IsNil(err))

	u, _ := url.Parse(res.Redirect)
	state := u.Query().Get("state")

	cres, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: res.Cookie.Value, Code: "c1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(cres.Link))
	qt.Check(t, qt.Equals(cres.Link.UserID, "u1"))
	qt.Check(t, qt.Equals(cres.ReturnTo, "/profile"))

	// Linking the same identity to another user is refused by default.
	login2, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "portal"}, Username: "carol", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	res, err = a.BeginExternalLink(context.Background(), ExternalLinkRequest{Provider: "corp", Token: login2.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))

	u, _ = url.Parse(res.Redirect)

	_, err = a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: u.Query().Get("state"), Binding: res.Cookie.Value, Code: "c2"})
	qt.Check(t, qt.IsTrue(errors.Is(err, provider.ErrIdentityLinked)))

	var oe *OAuthError
	qt.Assert(t, qt.IsTrue(errors.As(err, &oe)))
	qt.Check(t, qt.Equals(oe.StatusCode(), 409))
}

func TestExternalRelinkPolicyAllowsMove(t *testing.T) {
	store := provider.NewMemoryIdentityStore()
	cl := extPortalClient()
	cl.GrantTypes = []string{client.GrantTypePassword}
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, cl,
		IdentityStore(store),
		RelinkPolicy(provider.RelinkAuthorizerFunc(func(context.Context, *provider.IdentityLink, string) (bool, error) {
			return true, nil
		})))

	qt.Assert(t, qt.IsNil(store.Link(context.Background(), &provider.IdentityLink{UserID: "u2", Provider: "corp", Subject: "ext-1"})))

	login, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "portal"}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	res, err := a.BeginExternalLink(context.Background(), ExternalLinkRequest{Provider: "corp", Token: login.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))

	u, _ := url.Parse(res.Redirect)

	cres, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: u.Query().Get("state"), Binding: res.Cookie.Value, Code: "c1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(cres.Link.UserID, "u1"))

	// The identity moved: exactly one owner at all times.
	link, err := store.Lookup(context.Background(), "corp", "ext-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(link.UserID, "u1"))

	links, _, err := store.List(context.Background(), "u2", "", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(links, 0))
}

func TestExternalPerProviderClaimMapperOverride(t *testing.T) {
	entry := extProviderEntry("corp", "fake")
	entry.ClaimMapper = ClaimMapperFunc(func(context.Context, string, map[string]any) (UserInfo, error) {
		return UserInfo{}, errors.New("identity not allowed")
	})

	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{entry}, nil, extPortalClient())

	state, binding := beginAndExtractState(t, a, "corp", "portal", "")

	_, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: binding, Code: "c"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
}

func TestExternalAppWideClaimMapping(t *testing.T) {
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, extPortalClient(),
		ClaimMapping(ClaimMapperFunc(func(ctx context.Context, name string, raw map[string]any) (UserInfo, error) {
			info, err := provider.MapStandardClaims(ctx, name, raw)
			info.Scope += " mapped:" + name

			return info, err
		})))

	state, binding := beginAndExtractState(t, a, "corp", "portal", "")

	res, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: binding, Code: "c"})
	qt.Assert(t, qt.IsNil(err))

	_, sess, err := a.IntrospectToken(context.Background(), res.Login.Cookie.Value)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(sess.Scope, "mapped:corp"))
}

func TestExternalLoginDeferredByLogoutAfterAuth(t *testing.T) {
	entry := extProviderEntry("nosso", "fakelogout")
	entry.LogoutAfterAuth = true

	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{entry}, nil, extPortalClient())

	state, binding := beginAndExtractState(t, a, "nosso", "portal", "/home")

	res, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{
		Provider: "nosso", State: state, Binding: binding, Code: "c1", BaseURL: "https://app.example",
	})
	qt.Assert(t, qt.IsNil(err))

	// No session yet - the flow defers to the IdP end-session hop.
	qt.Check(t, qt.IsNil(res.Login))
	qt.Assert(t, qt.IsTrue(strings.HasPrefix(res.Redirect, "https://idp.example/logout?")))

	u, err := url.Parse(res.Redirect)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(u.Query().Get("post_logout_redirect_uri"), "/external/nosso/logout/callback"))

	pending := u.Query().Get("state")
	qt.Assert(t, qt.IsTrue(pending != ""))

	lres, err := a.ExternalLogoutCallback(context.Background(), ExternalLogoutCallbackRequest{Provider: "nosso", State: pending, Binding: binding})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(lres.Login))
	qt.Check(t, qt.Equals(lres.Login.ReturnTo, "/home"))

	_, sess, err := a.IntrospectToken(context.Background(), lres.Login.Cookie.Value)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.AuthProvider, "nosso"))

	// The pending-auth entry is single-use: a replay must not mint a second session.
	_, err = a.ExternalLogoutCallback(context.Background(), ExternalLogoutCallbackRequest{Provider: "nosso", State: pending, Binding: binding})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

func TestBrowserLogoutLocal(t *testing.T) {
	cl := extPortalClient()
	cl.GrantTypes = []string{client.GrantTypePassword}
	cl.PostLogoutRedirectURIs = []string{"https://app.example/bye"}

	a := newExternalTestAuth(t, nil, nil, cl)

	login, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "portal"}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	res, err := a.BrowserLogout(context.Background(), BrowserLogoutRequest{
		Token: login.Cookie.Value, PostLogoutRedirectURI: "https://app.example/bye",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Redirect, "https://app.example/bye"))
	qt.Assert(t, qt.IsNotNil(res.ClearCookie))
	qt.Check(t, qt.Equals(res.ClearCookie.MaxAge, -1))

	// The logout is authoritative: the cookie no longer introspects.
	_, _, err = a.IntrospectToken(context.Background(), login.Cookie.Value)
	qt.Check(t, qt.IsNotNil(err))

	// An unregistered target falls back to "/".
	login, err = a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "portal"}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	res, err = a.BrowserLogout(context.Background(), BrowserLogoutRequest{
		Token: login.Cookie.Value, PostLogoutRedirectURI: "https://evil.example/",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Redirect, "/"))
}

func TestBrowserLogoutFederated(t *testing.T) {
	cl := extPortalClient()
	cl.FederatedLogout = true
	cl.PostLogoutRedirectURIs = []string{"https://app.example/bye"}

	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fakelogout")}, nil, cl)

	state, binding := beginAndExtractState(t, a, "corp", "portal", "")

	res, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: binding, Code: "c1"})
	qt.Assert(t, qt.IsNil(err))

	lres, err := a.BrowserLogout(context.Background(), BrowserLogoutRequest{
		Token: res.Login.Cookie.Value, PostLogoutRedirectURI: "https://app.example/bye", BaseURL: "https://app.example",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(strings.HasPrefix(lres.Redirect, "https://idp.example/logout?")))

	u, err := url.Parse(lres.Redirect)
	qt.Assert(t, qt.IsNil(err))
	// The cached IdP id_token is passed as the hint.
	qt.Check(t, qt.Equals(u.Query().Get("id_token_hint"), "idt-c1"))

	logoutState := u.Query().Get("state")
	qt.Assert(t, qt.IsTrue(logoutState != ""))

	cres, err := a.ExternalLogoutCallback(context.Background(), ExternalLogoutCallbackRequest{Provider: "corp", State: logoutState})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNil(cres.Login))
	qt.Check(t, qt.Equals(cres.Redirect, "https://app.example/bye"))

	_, _, err = a.IntrospectToken(context.Background(), res.Login.Cookie.Value)
	qt.Check(t, qt.IsNotNil(err))
}

func TestBrowserLogoutWithoutFederationStaysLocal(t *testing.T) {
	// FederatedLogout unset: external session logs out locally only.
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fakelogout")}, nil, extPortalClient())

	state, binding := beginAndExtractState(t, a, "corp", "portal", "")

	res, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: binding, Code: "c1"})
	qt.Assert(t, qt.IsNil(err))

	lres, err := a.BrowserLogout(context.Background(), BrowserLogoutRequest{Token: res.Login.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(lres.Redirect, "/"))
}

func TestUnlinkIdentity(t *testing.T) {
	store := provider.NewMemoryIdentityStore()
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, extPortalClient(), IdentityStore(store))

	state, binding := beginAndExtractState(t, a, "corp", "portal", "")

	_, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: binding, Code: "c1"})
	qt.Assert(t, qt.IsNil(err))

	links, _, err := a.ListIdentities(context.Background(), "local-ext-1", "", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(links, 1))

	// Only the owner may unlink.
	err = a.UnlinkIdentity(context.Background(), "someone-else", links[0].ID)
	qt.Check(t, qt.IsTrue(errors.Is(err, provider.ErrLinkNotFound)))

	qt.Assert(t, qt.IsNil(a.UnlinkIdentity(context.Background(), "local-ext-1", links[0].ID)))

	links, _, err = a.ListIdentities(context.Background(), "local-ext-1", "", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(links, 0))
}

func TestExternalStateTTL(t *testing.T) {
	// Unset falls back to the documented default.
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, extPortalClient())
	qt.Check(t, qt.Equals(a.Config().ExternalStateTTL, 15*time.Minute))

	cfg := validConfig()
	cfg.ExternalStateTTL = 20 * time.Millisecond
	cfg.Providers = []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}

	users := extTestUsers{fakeUsers{
		users:     map[string]UserInfo{"alice": {ID: "u1", Name: "Alice", Scope: "openid"}},
		passwords: map[string]string{"alice": "secret123"},
	}}

	a2, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(extPortalClient()))
	qt.Assert(t, qt.IsNil(err))

	state, binding := beginAndExtractState(t, a2, "corp", "portal", "")

	// The stashed round-trip expires with the configured TTL.
	time.Sleep(50 * time.Millisecond)

	_, err = a2.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: binding, Code: "c1"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

func TestBeginExternalLinkRejectsThirdPartyAccessToken(t *testing.T) {
	cl := extPortalClient()
	cl.GrantTypes = []string{client.GrantTypePassword}
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, cl, IdentityStore(provider.NewMemoryIdentityStore()))

	login, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "portal"}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	_, err = a.BeginExternalLink(context.Background(), ExternalLinkRequest{Provider: "corp", Token: thirdPartyAccessToken(t, a, login.Cookie.Value)})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientScope))
}

func TestExternalCallbackRequiresBrowserBinding(t *testing.T) {
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, extPortalClient())

	// A callback without the starting browser's cookie is refused and burns the state.
	state, binding := beginAndExtractState(t, a, "corp", "portal", "")

	_, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Code: "c1"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	_, err = a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: binding, Code: "c1"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	state, _ = beginAndExtractState(t, a, "corp", "portal", "")

	_, err = a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: "not-the-cookie", Code: "c1"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

func TestExternalLinkCallbackRequiresStartingBrowser(t *testing.T) {
	cl := extPortalClient()
	cl.GrantTypes = []string{client.GrantTypePassword}
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, cl, IdentityStore(provider.NewMemoryIdentityStore()))

	login, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "portal"}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	res, err := a.BeginExternalLink(context.Background(), ExternalLinkRequest{Provider: "corp", Token: login.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(res.Cookie))

	u, _ := url.Parse(res.Redirect)

	// The victim's browser, lacking the attacker's binding cookie, cannot complete the link.
	_, err = a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: u.Query().Get("state"), Code: "c1"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

func TestExternalDeferredFinalizeRequiresBrowserBinding(t *testing.T) {
	entry := extProviderEntry("nosso", "fakelogout")
	entry.LogoutAfterAuth = true

	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{entry}, nil, extPortalClient())

	state, binding := beginAndExtractState(t, a, "nosso", "portal", "")

	res, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "nosso", State: state, Binding: binding, Code: "c1"})
	qt.Assert(t, qt.IsNil(err))
	// The binding cookie must survive the IdP logout hop.
	qt.Check(t, qt.IsNil(res.ClearCookie))

	u, _ := url.Parse(res.Redirect)

	_, err = a.ExternalLogoutCallback(context.Background(), ExternalLogoutCallbackRequest{Provider: "nosso", State: u.Query().Get("state")})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

func TestExternalLoginRequiresExternalUserProvider(t *testing.T) {
	plain := fakeUsers{
		users:     map[string]UserInfo{"alice": {ID: "u1", Name: "Alice", Scope: "openid"}},
		passwords: map[string]string{"alice": "secret123"},
	}

	cfg := validConfig()
	cfg.Providers = []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}

	// Without FindOrCreateUser and without an identity store no external login can ever succeed.
	_, err := New(newApp(t), cfg, plain, session.NewMemoryStore(), client.NewMemoryRegistry(extPortalClient()))
	qt.Check(t, qt.IsNotNil(err))

	// With an identity store, only a pre-linked identity resolves; an unknown subject is refused
	// rather than becoming a local user named after the IdP subject.
	store := provider.NewMemoryIdentityStore()
	a, err := New(newApp(t), cfg, plain, session.NewMemoryStore(), client.NewMemoryRegistry(extPortalClient()), IdentityStore(store))
	qt.Assert(t, qt.IsNil(err))

	state, binding := beginAndExtractState(t, a, "corp", "portal", "")

	_, err = a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: binding, Code: "c1"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeServerError))

	qt.Assert(t, qt.IsNil(store.Link(context.Background(), &provider.IdentityLink{UserID: "u1", Provider: "corp", Subject: "ext-1"})))

	state, binding = beginAndExtractState(t, a, "corp", "portal", "")

	res, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: binding, Code: "c1"})
	qt.Assert(t, qt.IsNil(err))

	info, _, err := a.IntrospectToken(context.Background(), res.Login.Cookie.Value)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.ID, "u1"))
}

func TestBrowserLogoutIgnoresStaleToken(t *testing.T) {
	cl := extPortalClient()
	cl.GrantTypes = []string{client.GrantTypePassword}
	cl.PostLogoutRedirectURIs = []string{"https://app.example/bye"}

	a := newExternalTestAuth(t, nil, nil, cl)

	login, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "portal"}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	rotated, err := a.Refresh(context.Background(), RefreshRequest{Token: login.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))

	res, err := a.BrowserLogout(context.Background(), BrowserLogoutRequest{
		Token: login.Cookie.Value, PostLogoutRedirectURI: "https://app.example/bye",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(res.ClearCookie))

	// The browser still gets its cookie cleared and its registered post-logout hop...
	qt.Check(t, qt.Equals(res.Redirect, "https://app.example/bye"))

	// ...but the live session is untouched.
	_, _, err = a.IntrospectToken(context.Background(), rotated.Cookie.Value)
	qt.Check(t, qt.IsNil(err))
}

func TestExternalStartIsRateLimitedPerCaller(t *testing.T) {
	cfg := validConfig()
	cfg.Providers = []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}
	cfg.Throttle = contract.ThrottleConfig{
		Enabled: true, MaxAttempts: 5, Window: time.Minute, LockoutTTL: time.Minute,
		ExternalStartMax: 2,
	}

	users := extTestUsers{fakeUsers{
		users:     map[string]UserInfo{"alice": {ID: "u1", Name: "Alice", Scope: "openid"}},
		passwords: map[string]string{"alice": "secret123"},
	}}

	cl := extPortalClient()
	cl.GrantTypes = []string{client.GrantTypePassword}
	cl.AllowedAuthMethods = []string{client.AuthMethodPassword, "corp"}

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(cl))
	qt.Assert(t, qt.IsNil(err))

	begin := func(ip string) error {
		_, err := a.BeginExternalLogin(context.Background(), ExternalLoginRequest{Provider: "corp", ClientID: "portal", IP: ip})

		return err
	}

	qt.Assert(t, qt.IsNil(begin("10.0.0.1")))
	qt.Assert(t, qt.IsNil(begin("10.0.0.1")))

	// The budget is spent, so no further round-trip state is written for this caller.
	qt.Check(t, qt.Equals(oauthErrorCode(t, begin("10.0.0.1")), ErrCodeSlowDown))

	// It is per caller, and separate from the credential lockout.
	qt.Check(t, qt.IsNil(begin("10.0.0.2")))

	_, err = a.Login(context.Background(), LoginRequest{
		Credentials: ClientCredentials{ClientID: "portal"}, Username: "alice", Password: "secret123", IP: "10.0.0.1",
	})
	qt.Check(t, qt.IsNil(err))
}

func TestExternalStartWithoutIPIsNotThrottled(t *testing.T) {
	cfg := validConfig()
	cfg.Providers = []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}
	cfg.Throttle = contract.ThrottleConfig{
		Enabled: true, MaxAttempts: 5, Window: time.Minute, LockoutTTL: time.Minute,
		ExternalStartMax: 2,
	}

	cl := extPortalClient()
	cl.AllowedAuthMethods = []string{client.AuthMethodPassword, "corp"}

	a, err := New(newApp(t), cfg, extTestUsers{fakeUsers{}}, session.NewMemoryStore(), client.NewMemoryRegistry(cl))
	qt.Assert(t, qt.IsNil(err))

	// Callers with no known IP never share one bucket that would lock everyone out.
	for range 3 {
		_, err := a.BeginExternalLogin(context.Background(), ExternalLoginRequest{Provider: "corp", ClientID: "portal"})
		qt.Check(t, qt.IsNil(err))
	}
}

func TestBrowserLogoutConfirmation(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)

	cfg := validConfig()
	cfg.LogoutInvalidatesCookie = true
	cfg.LogoutPolicy = LogoutPolicyConfirm
	cfg.Keys = keySetConfig(priv, pub)

	cl := extPortalClient()
	cl.GrantTypes = []string{client.GrantTypePassword}
	cl.ResponseMode = client.ResponseModeJSON
	cl.Scopes = []string{ScopeOpenID}

	users := extTestUsers{fakeUsers{
		users:     map[string]UserInfo{"alice": {ID: "u1", Name: "Alice", Scope: "openid"}},
		passwords: map[string]string{"alice": "secret123"},
	}}

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(cl))
	qt.Assert(t, qt.IsNil(err))

	login := func() LoginResult {
		res, err := a.Login(context.Background(), LoginRequest{
			Credentials: ClientCredentials{ClientID: "portal"}, Username: "alice", Password: "secret123",
			BaseURL: "https://issuer.example",
		})
		qt.Assert(t, qt.IsNil(err))

		return res
	}

	// A bare navigation ends nothing and does not even clear the cookie.
	first := login()

	res, err := a.BrowserLogout(context.Background(), BrowserLogoutRequest{Token: first.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(res.ConfirmationRequired))
	qt.Check(t, qt.IsNil(res.ClearCookie))

	_, _, err = a.IntrospectToken(context.Background(), first.Cookie.Value)
	qt.Check(t, qt.IsNil(err))

	// Confirming it does.
	res, err = a.BrowserLogout(context.Background(), BrowserLogoutRequest{Token: first.Cookie.Value, Confirmed: true})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(res.ConfirmationRequired))

	_, _, err = a.IntrospectToken(context.Background(), first.Cookie.Value)
	qt.Check(t, qt.IsNotNil(err))

	// So does an id_token this server issued for the session.
	second := login()
	qt.Assert(t, qt.IsTrue(second.IDToken != ""))

	res, err = a.BrowserLogout(context.Background(), BrowserLogoutRequest{Token: second.Cookie.Value, IDTokenHint: second.IDToken})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(res.ConfirmationRequired))

	_, _, err = a.IntrospectToken(context.Background(), second.Cookie.Value)
	qt.Check(t, qt.IsNotNil(err))

	// A hint for somebody else's session does not.
	third := login()

	res, err = a.BrowserLogout(context.Background(), BrowserLogoutRequest{Token: third.Cookie.Value, IDTokenHint: "not-a-token"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(res.ConfirmationRequired))

	_, _, err = a.IntrospectToken(context.Background(), third.Cookie.Value)
	qt.Check(t, qt.IsNil(err))
}

func TestBrowserLogoutWithoutConfirmationSettingIsUnchanged(t *testing.T) {
	cl := extPortalClient()
	cl.GrantTypes = []string{client.GrantTypePassword}

	a := newExternalTestAuth(t, nil, nil, cl)

	login, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "portal"}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	res, err := a.BrowserLogout(context.Background(), BrowserLogoutRequest{Token: login.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(res.ConfirmationRequired))
	qt.Assert(t, qt.IsNotNil(res.ClearCookie))

	_, _, err = a.IntrospectToken(context.Background(), login.Cookie.Value)
	qt.Check(t, qt.IsNotNil(err))
}

func TestBrowserLogoutRequiresIDTokenHint(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)

	cfg := validConfig()
	cfg.LogoutInvalidatesCookie = true
	cfg.LogoutPolicy = LogoutPolicyIDTokenHint
	cfg.Keys = keySetConfig(priv, pub)

	cl := extPortalClient()
	cl.GrantTypes = []string{client.GrantTypePassword}
	cl.ResponseMode = client.ResponseModeJSON
	cl.Scopes = []string{ScopeOpenID}

	users := extTestUsers{fakeUsers{
		users:     map[string]UserInfo{"alice": {ID: "u1", Name: "Alice", Scope: "openid"}},
		passwords: map[string]string{"alice": "secret123"},
	}}

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(cl))
	qt.Assert(t, qt.IsNil(err))

	login := func() LoginResult {
		res, err := a.Login(context.Background(), LoginRequest{
			Credentials: ClientCredentials{ClientID: "portal"}, Username: "alice", Password: "secret123",
			BaseURL: "https://issuer.example",
		})
		qt.Assert(t, qt.IsNil(err))

		return res
	}

	// Without a hint the request is refused outright; there is no confirmation path.
	first := login()

	_, err = a.BrowserLogout(context.Background(), BrowserLogoutRequest{Token: first.Cookie.Value})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	// Claiming confirmation does not substitute for the hint either.
	_, err = a.BrowserLogout(context.Background(), BrowserLogoutRequest{Token: first.Cookie.Value, Confirmed: true})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	_, _, err = a.IntrospectToken(context.Background(), first.Cookie.Value)
	qt.Check(t, qt.IsNil(err))

	// The hint this server issued for the session ends it.
	res, err := a.BrowserLogout(context.Background(), BrowserLogoutRequest{Token: first.Cookie.Value, IDTokenHint: first.IDToken})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(res.ConfirmationRequired))

	_, _, err = a.IntrospectToken(context.Background(), first.Cookie.Value)
	qt.Check(t, qt.IsNotNil(err))
}
