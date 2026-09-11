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
func beginAndExtractState(t *testing.T, a *Auth, providerName, clientID, returnTo string) string {
	t.Helper()

	res, err := a.BeginExternalLogin(context.Background(), ExternalLoginRequest{Provider: providerName, ClientID: clientID, ReturnTo: returnTo})
	qt.Assert(t, qt.IsNil(err))

	u, err := url.Parse(res.Redirect)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(u.Query().Get("code_challenge") != ""))
	qt.Check(t, qt.IsTrue(u.Query().Get("nonce") != ""))

	state := u.Query().Get("state")
	qt.Assert(t, qt.IsTrue(state != ""))

	// The eventually-consistent memory cache must apply the state write before the callback.
	settle()

	return state
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

	state := beginAndExtractState(t, a, "corp", "portal", "/dashboard")

	res, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{
		Provider: "corp", State: state, Code: "code-1", RequestTLS: true, BaseURL: "https://app.example",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(res.Login))

	qt.Check(t, qt.Equals(res.Login.Status, session.StatusActive))
	qt.Check(t, qt.Equals(res.Login.ReturnTo, "/dashboard"))
	qt.Assert(t, qt.IsNotNil(res.Login.Cookie))

	settle()

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
	state := beginAndExtractState(t, a, "corp", "portal", "")
	_, err = a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "other", State: state, Code: "c"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	// Replay: a consumed state cannot be used again.
	state = beginAndExtractState(t, a, "corp", "portal", "")

	_, err = a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Code: "c"})
	qt.Assert(t, qt.IsNil(err))

	_, err = a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Code: "c"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

func TestExternalCallbackUpstreamError(t *testing.T) {
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, extPortalClient())

	state := beginAndExtractState(t, a, "corp", "portal", "")

	_, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Error: "access_denied"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeAccessDenied))
}

func TestExternalLoginAutoLinksAndResolvesViaIdentityStore(t *testing.T) {
	store := provider.NewMemoryIdentityStore()
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, extPortalClient(), IdentityStore(store))

	state := beginAndExtractState(t, a, "corp", "portal", "")

	res, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Code: "c1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(res.Login))

	// First login auto-linked the resolved user.
	link, err := store.Lookup(context.Background(), "corp", "ext-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(link.UserID, "local-ext-1"))

	// Second login resolves through the link (and touches LastUsedAt).
	state = beginAndExtractState(t, a, "corp", "portal", "")

	res, err = a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Code: "c2"})
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

	login, err := a.Login(context.Background(), LoginRequest{ClientID: "portal", Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	res, err := a.BeginExternalLink(context.Background(), ExternalLinkRequest{Provider: "corp", Token: login.Cookie.Value, ReturnTo: "/profile"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	u, _ := url.Parse(res.Redirect)
	state := u.Query().Get("state")

	cres, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Code: "c1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(cres.Link))
	qt.Check(t, qt.Equals(cres.Link.UserID, "u1"))
	qt.Check(t, qt.Equals(cres.ReturnTo, "/profile"))

	// Linking the same identity to another user is refused by default.
	login2, err := a.Login(context.Background(), LoginRequest{ClientID: "portal", Username: "carol", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	res, err = a.BeginExternalLink(context.Background(), ExternalLinkRequest{Provider: "corp", Token: login2.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))
	settle()

	u, _ = url.Parse(res.Redirect)

	_, err = a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: u.Query().Get("state"), Code: "c2"})
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

	login, err := a.Login(context.Background(), LoginRequest{ClientID: "portal", Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	res, err := a.BeginExternalLink(context.Background(), ExternalLinkRequest{Provider: "corp", Token: login.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))
	settle()

	u, _ := url.Parse(res.Redirect)

	cres, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: u.Query().Get("state"), Code: "c1"})
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

	state := beginAndExtractState(t, a, "corp", "portal", "")

	_, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Code: "c"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
}

func TestExternalAppWideClaimMapping(t *testing.T) {
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, extPortalClient(),
		ClaimMapping(ClaimMapperFunc(func(ctx context.Context, name string, raw map[string]any) (UserInfo, error) {
			info, err := provider.MapStandardClaims(ctx, name, raw)
			info.Scope += " mapped:" + name

			return info, err
		})))

	state := beginAndExtractState(t, a, "corp", "portal", "")

	res, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Code: "c"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	_, sess, err := a.IntrospectToken(context.Background(), res.Login.Cookie.Value)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(sess.Scope, "mapped:corp"))
}

func TestExternalLoginDeferredByLogoutAfterAuth(t *testing.T) {
	entry := extProviderEntry("nosso", "fakelogout")
	entry.LogoutAfterAuth = true

	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{entry}, nil, extPortalClient())

	state := beginAndExtractState(t, a, "nosso", "portal", "/home")

	res, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{
		Provider: "nosso", State: state, Code: "c1", BaseURL: "https://app.example",
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

	settle()

	lres, err := a.ExternalLogoutCallback(context.Background(), ExternalLogoutCallbackRequest{Provider: "nosso", State: pending})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(lres.Login))
	qt.Check(t, qt.Equals(lres.Login.ReturnTo, "/home"))

	settle()

	_, sess, err := a.IntrospectToken(context.Background(), lres.Login.Cookie.Value)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.AuthProvider, "nosso"))

	// The pending-auth entry is single-use: a replay must not mint a second session.
	_, err = a.ExternalLogoutCallback(context.Background(), ExternalLogoutCallbackRequest{Provider: "nosso", State: pending})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

func TestBrowserLogoutLocal(t *testing.T) {
	cl := extPortalClient()
	cl.GrantTypes = []string{client.GrantTypePassword}
	cl.PostLogoutRedirectURIs = []string{"https://app.example/bye"}

	a := newExternalTestAuth(t, nil, nil, cl)

	login, err := a.Login(context.Background(), LoginRequest{ClientID: "portal", Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	res, err := a.BrowserLogout(context.Background(), BrowserLogoutRequest{
		Token: login.Cookie.Value, PostLogoutRedirectURI: "https://app.example/bye",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Redirect, "https://app.example/bye"))
	qt.Assert(t, qt.IsNotNil(res.ClearCookie))
	qt.Check(t, qt.Equals(res.ClearCookie.MaxAge, -1))

	settle()

	// The logout is authoritative: the cookie no longer introspects.
	_, _, err = a.IntrospectToken(context.Background(), login.Cookie.Value)
	qt.Check(t, qt.IsNotNil(err))

	// An unregistered target falls back to "/".
	login, err = a.Login(context.Background(), LoginRequest{ClientID: "portal", Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))
	settle()

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

	state := beginAndExtractState(t, a, "corp", "portal", "")

	res, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Code: "c1"})
	qt.Assert(t, qt.IsNil(err))
	settle()

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

	settle()

	cres, err := a.ExternalLogoutCallback(context.Background(), ExternalLogoutCallbackRequest{Provider: "corp", State: logoutState})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNil(cres.Login))
	qt.Check(t, qt.Equals(cres.Redirect, "https://app.example/bye"))

	settle()

	_, _, err = a.IntrospectToken(context.Background(), res.Login.Cookie.Value)
	qt.Check(t, qt.IsNotNil(err))
}

func TestBrowserLogoutWithoutFederationStaysLocal(t *testing.T) {
	// FederatedLogout unset: external session logs out locally only.
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fakelogout")}, nil, extPortalClient())

	state := beginAndExtractState(t, a, "corp", "portal", "")

	res, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Code: "c1"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	lres, err := a.BrowserLogout(context.Background(), BrowserLogoutRequest{Token: res.Login.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(lres.Redirect, "/"))
}

func TestUnlinkIdentity(t *testing.T) {
	store := provider.NewMemoryIdentityStore()
	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{extProviderEntry("corp", "fake")}, nil, extPortalClient(), IdentityStore(store))

	state := beginAndExtractState(t, a, "corp", "portal", "")

	_, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Code: "c1"})
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

	state := beginAndExtractState(t, a2, "corp", "portal", "")

	// The stashed round-trip expires with the configured TTL.
	time.Sleep(50 * time.Millisecond)

	_, err = a2.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Code: "c1"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}
