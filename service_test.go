package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
)

// settle waits for the eventually-consistent memory cache backing the default JTI store to
// apply a write (see jti/allowlist_test.go's identical helper).
func settle() { time.Sleep(10 * time.Millisecond) }

type fakeUsers struct {
	users     map[string]UserInfo
	passwords map[string]string
}

func (f fakeUsers) Authenticate(_ context.Context, username, password string) (UserInfo, error) {
	pw, ok := f.passwords[username]
	if !ok || pw != password {
		return UserInfo{}, ErrInvalidCredentials
	}

	return f.users[username], nil
}

func (f fakeUsers) GetUser(_ context.Context, id string) (UserInfo, error) {
	for _, u := range f.users {
		if u.ID == id {
			return u, nil
		}
	}

	return UserInfo{}, ErrUserNotFound
}

func newServiceTestAuth(t *testing.T, cl *client.Client) *Auth {
	t.Helper()

	users := fakeUsers{
		users:     map[string]UserInfo{"alice": {ID: "u1", Name: "Alice", Email: "alice@example.com", Scope: "openid profile"}},
		passwords: map[string]string{"alice": "secret123"},
	}

	// validConfig() is a bare struct literal (bypassing viper's Bind defaults), so
	// LogoutInvalidatesCookie's own "default true" must be set explicitly here.
	cfg := validConfig()
	cfg.LogoutInvalidatesCookie = true

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(cl))
	qt.Assert(t, qt.IsNil(err))

	return a
}

func oauthErrorCode(t *testing.T, err error) ErrorCode {
	t.Helper()

	var oe *OAuthError
	qt.Assert(t, qt.IsTrue(errors.As(err, &oe)))

	return oe.Code
}

func TestLoginJSONResponseMode(t *testing.T) {
	a := newServiceTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})

	res, err := a.Login(context.Background(), LoginRequest{
		ClientID: "spa", Username: "alice", Password: "secret123", RequestTLS: true, BasePath: "/",
	})
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(res.Status, session.StatusActive))
	qt.Assert(t, qt.IsNotNil(res.Cookie))
	qt.Check(t, qt.IsTrue(res.Cookie.Value != ""))
	qt.Check(t, qt.Equals(res.Cookie.Secure, true))
	qt.Check(t, qt.IsTrue(res.AccessToken != ""))
	qt.Check(t, qt.Equals(res.ExpiresIn, int(20*time.Minute/time.Second)))
	qt.Check(t, qt.Equals(res.Redirect, ""))
}

func TestLoginRedirectResponseMode(t *testing.T) {
	a := newServiceTestAuth(t, &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeRedirect,
	})

	res, err := a.Login(context.Background(), LoginRequest{
		ClientID: "ssr", Username: "alice", Password: "secret123", ReturnTo: "/dashboard",
	})
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(res.AccessToken, ""))
	qt.Check(t, qt.Equals(res.Redirect, "/dashboard"))

	// No ReturnTo defaults to "/".
	res2, err := a.Login(context.Background(), LoginRequest{ClientID: "ssr", Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res2.Redirect, "/"))
}

func TestLoginCookieResponseMode(t *testing.T) {
	a := newServiceTestAuth(t, &client.Client{
		ID: "cookie-app", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeCookie,
	})

	res, err := a.Login(context.Background(), LoginRequest{ClientID: "cookie-app", Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(res.AccessToken, ""))
	qt.Check(t, qt.Equals(res.Redirect, ""))
	qt.Assert(t, qt.IsNotNil(res.Cookie))
	qt.Check(t, qt.IsTrue(res.Cookie.Value != ""))
}

func TestLoginInvalidCredentials(t *testing.T) {
	a := newServiceTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword}, ResponseMode: client.ResponseModeJSON,
	})

	_, err := a.Login(context.Background(), LoginRequest{ClientID: "spa", Username: "alice", Password: "wrong"})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
}

func TestLoginUnknownClient(t *testing.T) {
	a := newServiceTestAuth(t, &client.Client{ID: "spa"})

	_, err := a.Login(context.Background(), LoginRequest{ClientID: "does-not-exist", Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidClient))
}

func TestLoginUnauthorizedClient(t *testing.T) {
	// GrantTypes does not include "password".
	noGrant := newServiceTestAuth(t, &client.Client{ID: "m2m", GrantTypes: []string{"client_credentials"}})
	_, err := noGrant.Login(context.Background(), LoginRequest{ClientID: "m2m", Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnauthorizedClient))

	// GrantTypes allows it, but AllowedAuthMethods excludes password.
	noMethod := newServiceTestAuth(t, &client.Client{
		ID: "external-only", GrantTypes: []string{client.GrantTypePassword}, AllowedAuthMethods: []string{"azure"},
	})
	_, err = noMethod.Login(context.Background(), LoginRequest{ClientID: "external-only", Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnauthorizedClient))
}

func TestRefreshRotatesCookie(t *testing.T) {
	a := newServiceTestAuth(t, &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeCookie,
	})

	login, err := a.Login(context.Background(), LoginRequest{ClientID: "ssr", Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	refresh, err := a.Refresh(context.Background(), RefreshRequest{Token: login.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Not(qt.Equals(refresh.Cookie.Value, login.Cookie.Value)))
	settle()

	// The rotated cookie introspects fine.
	info, _, err := a.IntrospectToken(context.Background(), refresh.Cookie.Value)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.ID, "u1"))
}

func TestRefreshReplayOfRotatedCookieFailsClosed(t *testing.T) {
	a := newServiceTestAuth(t, &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeCookie,
	})

	login, err := a.Login(context.Background(), LoginRequest{ClientID: "ssr", Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	refresh, err := a.Refresh(context.Background(), RefreshRequest{Token: login.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))
	settle()

	// Replaying the now-superseded original cookie fails closed (forced re-login) rather than
	// being silently accepted - the underlying jti cache can't distinguish this from ordinary
	// cache loss, so it does not additionally revoke the session (see jti.Store's own docs).
	_, err = a.Refresh(context.Background(), RefreshRequest{Token: login.Cookie.Value})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeLoginRequired))

	// The session itself was never revoked, so the rotated cookie keeps working.
	_, _, err = a.IntrospectToken(context.Background(), refresh.Cookie.Value)
	qt.Check(t, qt.IsNil(err))
}

func TestRefreshMissingOrInvalidToken(t *testing.T) {
	a := newServiceTestAuth(t, &client.Client{ID: "ssr"})

	_, err := a.Refresh(context.Background(), RefreshRequest{})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeLoginRequired))

	_, err = a.Refresh(context.Background(), RefreshRequest{Token: "garbage"})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeLoginRequired))
}

func TestLogoutRevokesSessionAndClearsCookie(t *testing.T) {
	a := newServiceTestAuth(t, &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeCookie,
	})

	login, err := a.Login(context.Background(), LoginRequest{ClientID: "ssr", Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	out, err := a.Logout(context.Background(), LogoutRequest{Token: login.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(out.ClearCookie))
	qt.Check(t, qt.IsTrue(out.ClearCookie.MaxAge < 0))
	settle()

	_, _, err = a.IntrospectToken(context.Background(), login.Cookie.Value)
	qt.Check(t, qt.IsNotNil(err))
}

func TestLogoutWithoutTokenStillClearsCookie(t *testing.T) {
	a := newServiceTestAuth(t, &client.Client{ID: "ssr"})

	out, err := a.Logout(context.Background(), LogoutRequest{})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(out.ClearCookie))
	qt.Check(t, qt.IsTrue(out.ClearCookie.MaxAge < 0))
}

func TestIntrospectTokenFailureCases(t *testing.T) {
	a := newServiceTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})

	_, _, err := a.IntrospectToken(context.Background(), "")
	qt.Check(t, qt.IsNotNil(err))

	_, _, err = a.IntrospectToken(context.Background(), "not-a-real-token")
	qt.Check(t, qt.IsNotNil(err))

	login, err := a.Login(context.Background(), LoginRequest{ClientID: "spa", Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	_, err = a.Logout(context.Background(), LogoutRequest{Token: login.AccessToken})
	qt.Assert(t, qt.IsNil(err))
	settle()

	// Revoked session - the access token no longer introspects.
	_, _, err = a.IntrospectToken(context.Background(), login.AccessToken)
	qt.Check(t, qt.IsNotNil(err))
}

func TestListAndRevokeSession(t *testing.T) {
	a := newServiceTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})

	login, err := a.Login(context.Background(), LoginRequest{ClientID: "spa", Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))
	settle()

	info, sess, err := a.IntrospectToken(context.Background(), login.AccessToken)
	qt.Assert(t, qt.IsNil(err))

	sessions, _, err := a.ListSessions(context.Background(), info.ID, nil, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(sessions, 1))

	// Another user cannot revoke it.
	err = a.RevokeSession(context.Background(), "someone-else", sess.ID)
	qt.Check(t, qt.IsNotNil(err))

	err = a.RevokeSession(context.Background(), info.ID, sess.ID)
	qt.Assert(t, qt.IsNil(err))
	settle()

	_, _, err = a.IntrospectToken(context.Background(), login.AccessToken)
	qt.Check(t, qt.IsNotNil(err))
}
