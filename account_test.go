package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/mfa"
	"azugo.io/auth/reset"
	"azugo.io/auth/session"

	"azugo.io/core/cache"
	"github.com/go-quicktest/qt"
)

// accountUsers implements every self-service extension over an in-memory user table.
type accountUsers struct {
	mu        sync.Mutex
	users     map[string]UserInfo
	passwords map[string]string
	profiles  map[string]map[string]any
	// delivered records the reset secrets handed out per user ID; deliveries signals each one.
	delivered  map[string][]string
	deliveries chan string
	// deliverErr fails delivery when set.
	deliverErr error
	// registerErr fails registration when set.
	registerErr error
}

// deliver records the secret a reset method hands out; "sms" needs a phone number.
func (f *accountUsers) deliver(channel string) reset.Deliverer {
	return testDeliverer{users: f, channel: channel}
}

// awaitDelivery returns the next delivered secret.
func (f *accountUsers) awaitDelivery(t *testing.T) string {
	t.Helper()

	select {
	case secret := <-f.deliveries:
		return secret
	case <-time.After(2 * time.Second):
		t.Fatal("no reset secret was delivered")

		return ""
	}
}

// testDeliverer records the secrets a reset method hands out; "sms" needs a phone number.
type testDeliverer struct {
	users   *accountUsers
	channel string
}

func (d testDeliverer) Available(info UserInfo) bool {
	return d.channel != "sms" || info.Claims["phone_number"] != nil
}

func (d testDeliverer) Deliver(_ context.Context, info UserInfo, _, secret string) error {
	d.users.mu.Lock()
	d.users.delivered[info.ID] = append(d.users.delivered[info.ID], secret)
	d.users.mu.Unlock()

	d.users.deliveries <- secret

	return d.users.deliverErr
}

// resetMethods is the registry the account tests run with.
func (f *accountUsers) resetMethods() reset.Registry {
	return reset.Methods(map[string]reset.Method{"email": reset.Link(f.deliver("email")), "sms": reset.Code(f.deliver("sms"), 6)})
}

func newAccountUsers() *accountUsers {
	return &accountUsers{
		users: map[string]UserInfo{
			"alice": {ID: "u1", Name: "Alice", Email: "alice@example.com", Scope: "openid profile"},
			"fresh": {ID: "u3", Name: "Fresh", Email: "fresh@example.com", Scope: "openid profile", RequiresPasswordChange: true, Claims: map[string]any{"phone_number": "+37120000000"}},
		},
		passwords:  map[string]string{"alice": "secret123", "fresh": "changeme"},
		profiles:   map[string]map[string]any{},
		delivered:  map[string][]string{},
		deliveries: make(chan string, 64),
	}
}

func (f *accountUsers) username(userID string) (string, bool) {
	for name, u := range f.users {
		if u.ID == userID {
			return name, true
		}
	}

	return "", false
}

func (f *accountUsers) Authenticate(_ context.Context, username, password string) (UserInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	pw, ok := f.passwords[username]
	if !ok || pw != password {
		return UserInfo{}, ErrInvalidCredentials
	}

	return f.users[username], nil
}

func (f *accountUsers) GetUser(_ context.Context, id string) (UserInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	name, ok := f.username(id)
	if !ok {
		return UserInfo{}, ErrUserNotFound
	}

	return f.users[name], nil
}

func (f *accountUsers) Register(_ context.Context, req RegistrationRequest) (UserInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.registerErr != nil {
		return UserInfo{}, f.registerErr
	}

	if _, ok := f.users[req.Username]; ok {
		return UserInfo{}, ErrUserAlreadyExists
	}

	info := UserInfo{ID: "u-" + req.Username, Name: req.Username, Email: req.Email, Scope: "openid profile"}
	f.users[req.Username] = info
	f.passwords[req.Username] = req.Password

	return info, nil
}

func (f *accountUsers) ChangePassword(_ context.Context, userID, currentPassword, newPassword string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	name, ok := f.username(userID)
	if !ok {
		return ErrUserNotFound
	}

	if f.passwords[name] != currentPassword {
		return ErrInvalidCredentials
	}

	f.passwords[name] = newPassword

	return nil
}

func (f *accountUsers) SetPassword(_ context.Context, userID, newPassword string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	name, ok := f.username(userID)
	if !ok {
		return ErrUserNotFound
	}

	f.passwords[name] = newPassword

	u := f.users[name]
	u.RequiresPasswordChange = false
	f.users[name] = u

	return nil
}

func (f *accountUsers) FindUser(_ context.Context, identifier string) (UserInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for name, u := range f.users {
		if name == identifier || u.Email == identifier {
			return u, nil
		}
	}

	return UserInfo{}, ErrUserNotFound
}

func (f *accountUsers) ResetPassword(ctx context.Context, userID, newPassword string) error {
	return f.SetPassword(ctx, userID, newPassword)
}

func (f *accountUsers) GetProfile(_ context.Context, userID string) (map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.profiles[userID], nil
}

func (f *accountUsers) UpdateProfile(_ context.Context, userID string, data map[string]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.profiles[userID] = data

	return nil
}

func newAccountTestAuth(t *testing.T, cl *client.Client, opts ...Option) (*Auth, *accountUsers) {
	t.Helper()

	cfg := validConfig()

	return newAccountTestAuthWithConfig(t, cfg, cl, opts...)
}

func newAccountTestAuthWithConfig(t *testing.T, cfg *Configuration, cl *client.Client, opts ...Option) (*Auth, *accountUsers) {
	t.Helper()

	return newAccountTestAuthWithStore(t, cfg, session.NewMemoryStore(), cl, opts...)
}

func newAccountTestAuthWithStore(t *testing.T, cfg *Configuration, store session.Store, cl *client.Client, opts ...Option) (*Auth, *accountUsers) {
	t.Helper()

	users := newAccountUsers()

	a, err := New(newApp(t), cfg, users, store, client.NewMemoryRegistry(cl), append([]Option{PasswordResetRegistry(users.resetMethods())}, opts...)...)
	qt.Assert(t, qt.IsNil(err))

	return a, users
}

// registeringClient is a JSON portal client that signs registered accounts in.
func registeringClient() *client.Client {
	cl := mfaClient(client.MFAPolicyDisabled)
	cl.RegistrationPolicy = client.RegistrationPolicySignIn

	return cl
}

func TestRegisterCreatesAccountAndSignsIn(t *testing.T) {
	a, users := newAccountTestAuth(t, registeringClient())

	reg, err := a.Register(context.Background(), RegisterRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Email: "bob@example.com", Password: "pw123456",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(reg.UserID, "u-bob"))
	qt.Assert(t, qt.IsNotNil(reg.Login))

	res := *reg.Login
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))
	qt.Check(t, qt.IsTrue(res.AccessToken != ""))
	qt.Check(t, qt.DeepEquals(res.AMR, []string{"pwd"}))

	info, _, err := a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.ID, "u-bob"))
	qt.Check(t, qt.Equals(users.passwords["bob"], "pw123456"))

	// A taken username is a conflict.
	_, err = a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Password: "other-password-1"})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrUserAlreadyExists)))

	_, err = a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "eve"})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

func TestRegistrationPolicyGovernsRegistration(t *testing.T) {
	// The default client policy refuses registration outright.
	a, _ := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled))

	_, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Password: "pw123456"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnauthorizedClient))

	// require_login creates the account without a session.
	cl := mfaClient(client.MFAPolicyDisabled)
	cl.RegistrationPolicy = client.RegistrationPolicyRequireLogin
	a, users := newAccountTestAuth(t, cl)

	reg, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Password: "pw123456"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(reg.UserID, "u-bob"))
	qt.Check(t, qt.IsNil(reg.Login))
	qt.Check(t, qt.Equals(users.passwords["bob"], "pw123456"))

	res := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Password: "pw123456"})
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))

	// sign_in still needs the password grant to mint the session.
	cl = &client.Client{ID: "spa", GrantTypes: []string{client.GrantTypeAuthorizationCode}, ResponseMode: client.ResponseModeJSON, RegistrationPolicy: client.RegistrationPolicySignIn}
	a, _ = newAccountTestAuth(t, cl)

	_, err = a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Password: "pw123456"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnauthorizedClient))
}

func TestAccountMethodsRefuseWithoutInterfaces(t *testing.T) {
	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled))

	_, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Password: "pw"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: "x", NewPassword: "pw"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	_, err = a.RequestPasswordReset(context.Background(), PasswordResetRequest{Credentials: ClientCredentials{ClientID: "spa"}, Identifier: "alice"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	_, err = a.ResetPassword(context.Background(), PasswordResetConfirmRequest{Token: "x", NewPassword: "pw"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	_, err = a.Profile(context.Background(), "x")
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	// Without a PasswordChanger a flagged account cannot log in at all.
	res := loginAs(t, a, alice(""))
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))

	flagged := fakeUsers{
		users:     map[string]UserInfo{"fresh": {ID: "u3", RequiresPasswordChange: true}},
		passwords: map[string]string{"fresh": "changeme"},
	}

	b, err := New(newApp(t), validConfig(), flagged, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)))
	qt.Assert(t, qt.IsNil(err))

	_, err = b.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "fresh", Password: "changeme"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeAccessDenied))
}

func TestLoginRequiringPasswordChangeIsPendingUntilSet(t *testing.T) {
	a, users := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled))

	res := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "fresh", Password: "changeme"})
	qt.Assert(t, qt.Equals(res.Status, session.StatusPendingPasswordChange))
	qt.Check(t, qt.Equals(res.AccessToken, ""))
	qt.Assert(t, qt.IsTrue(res.StepToken != ""))
	qt.Assert(t, qt.IsNotNil(res.Cookie))

	_, _, err := a.IntrospectToken(context.Background(), res.StepToken)
	qt.Check(t, qt.IsNotNil(err))

	// The pending session never reaches the verifying path, so no current password is needed.
	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: res.StepToken})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	done, err := a.ChangePassword(context.Background(), PasswordChangeRequest{Token: res.StepToken, NewPassword: "brandnew1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))
	qt.Assert(t, qt.IsTrue(done.AccessToken != ""))
	qt.Check(t, qt.Equals(users.passwords["fresh"], "brandnew1"))
	qt.Check(t, qt.IsFalse(users.users["fresh"].RequiresPasswordChange))

	// The step token is retired with the pending phase.
	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: res.StepToken, NewPassword: "again"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))

	// The next login is a plain active one.
	again := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "fresh", Password: "brandnew1"})
	qt.Check(t, qt.Equals(again.Status, session.StatusActive))
}

func TestPasswordChangeComesAfterMFA(t *testing.T) {
	store := mfa.NewMemoryStore()
	a, users := newAccountTestAuth(t, mfaClient(client.MFAPolicyOptional), MFAStore(store))

	first := loginAs(t, a, alice(""))
	seed := enrollTOTP(t, a, first.AccessToken)

	u := users.users["alice"]
	u.RequiresPasswordChange = true
	users.users["alice"] = u

	// The password alone opens nothing: the second factor comes first.
	res := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(res.Status, session.StatusPendingMFA))

	_, err := a.ChangePassword(context.Background(), PasswordChangeRequest{Token: res.StepToken, NewPassword: "brandnew1"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))
	qt.Check(t, qt.Equals(users.passwords["alice"], "secret123"))

	next, err := a.VerifyMFA(context.Background(), MFAStepRequest{Token: res.StepToken, Response: map[string]any{"code": nextCode(t, seed)}})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(next.Status, session.StatusPendingPasswordChange))
	qt.Assert(t, qt.IsTrue(next.StepToken != ""))
	qt.Check(t, qt.Equals(next.AccessToken, ""))

	done, err := a.ChangePassword(context.Background(), PasswordChangeRequest{Token: next.StepToken, NewPassword: "brandnew1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))
	qt.Check(t, qt.IsTrue(done.AccessToken != ""))
	qt.Check(t, qt.DeepEquals(done.AMR, []string{"pwd", "otp", "mfa"}))
}

func TestChangePasswordOnActiveSessionVerifiesCurrent(t *testing.T) {
	a, users := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled))

	res := loginAs(t, a, alice(""))

	_, err := a.ChangePassword(context.Background(), PasswordChangeRequest{Token: res.AccessToken, NewPassword: "brandnew1"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: res.AccessToken, CurrentPassword: "wrong", NewPassword: "brandnew1"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
	qt.Check(t, qt.Equals(users.passwords["alice"], "secret123"))

	done, err := a.ChangePassword(context.Background(), PasswordChangeRequest{Token: res.AccessToken, CurrentPassword: "secret123", NewPassword: "brandnew1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))
	qt.Check(t, qt.IsNil(done.Cookie))
	qt.Check(t, qt.Equals(done.AccessToken, ""))
	qt.Check(t, qt.Equals(users.passwords["alice"], "brandnew1"))

	// The session stays valid after a self-service change; every other one is cut.
	_, _, err = a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Check(t, qt.IsNil(err))

	other := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "brandnew1"})

	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: res.AccessToken, CurrentPassword: "brandnew1", NewPassword: "newer-still1"})
	qt.Assert(t, qt.IsNil(err))

	_, _, err = a.IntrospectToken(context.Background(), other.AccessToken)
	qt.Check(t, qt.IsNotNil(err))

	_, _, err = a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Check(t, qt.IsNil(err))

	// Unless the request asks to keep them.
	kept := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "newer-still1"})

	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: res.AccessToken, CurrentPassword: "newer-still1", NewPassword: "final-one-1", KeepOtherSessions: true})
	qt.Assert(t, qt.IsNil(err))

	_, _, err = a.IntrospectToken(context.Background(), kept.AccessToken)
	qt.Check(t, qt.IsNil(err))
}

func TestChangePasswordGuessesAreThrottled(t *testing.T) {
	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a, _ := newAccountTestAuthWithConfig(t, cfg, mfaClient(client.MFAPolicyDisabled))

	res := loginAs(t, a, alice(""))

	var last error

	for range 3 {
		_, last = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: res.AccessToken, CurrentPassword: "wrong", NewPassword: "brandnew1", IP: "10.0.0.1"})
	}

	qt.Check(t, qt.Equals(oauthErrorCode(t, last), ErrCodeSlowDown))
}

func TestResetRequestsDoNotSpendLoginBudget(t *testing.T) {
	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a, _ := newAccountTestAuthWithConfig(t, cfg, mfaClient(client.MFAPolicyDisabled))

	for range 2 {
		_, err := a.RequestPasswordReset(context.Background(), PasswordResetRequest{Credentials: ClientCredentials{ClientID: "spa"}, Identifier: "nobody", IP: "10.0.0.1"})
		qt.Assert(t, qt.IsNil(err))
	}

	// The source is capped for further reset requests, but may still log in.
	_, err := a.RequestPasswordReset(context.Background(), PasswordResetRequest{Credentials: ClientCredentials{ClientID: "spa"}, Identifier: "nobody", IP: "10.0.0.1"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))

	in := alice("")
	in.IP = "10.0.0.1"
	res := loginAs(t, a, in)
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))

	// Registrations are capped on their own quota too.
	cfg.Throttle.RegistrationMax = 2
	a, _ = newAccountTestAuthWithConfig(t, cfg, registeringClient())

	for i := range 2 {
		_, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "new" + string(rune('a'+i)), Password: "pw123456", IP: "10.0.0.2"})
		qt.Assert(t, qt.IsNil(err))
	}

	_, err = a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "newc", Password: "pw123456", IP: "10.0.0.2"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))

	in.IP = "10.0.0.2"
	res = loginAs(t, a, in)
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))
}

func TestRegistrationQuotaCountsEveryAttempt(t *testing.T) {
	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{RegistrationMax: 2, Window: time.Minute}

	a, users := newAccountTestAuthWithConfig(t, cfg, registeringClient())
	in := RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "dave", Password: "pw123456", IP: "10.0.0.3"}

	// Every attempt counts, whatever the provider answered.
	users.registerErr = errors.New("db down")

	_, err := a.Register(context.Background(), in)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeServerError))

	users.registerErr = nil

	_, err = a.Register(context.Background(), in)
	qt.Assert(t, qt.IsNil(err))

	_, err = a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "erin", Password: "pw123456", IP: "10.0.0.3"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))
}

func TestChangePasswordRedirectModeReturnsLocalTarget(t *testing.T) {
	a, _ := newAccountTestAuth(t, &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeRedirect,
	})

	res := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "ssr"}, Username: "alice", Password: "secret123"})

	done, err := a.ChangePassword(context.Background(), PasswordChangeRequest{
		Token: res.Cookie.Value, CurrentPassword: "secret123", NewPassword: "brandnew1", ReturnTo: "https://evil.example/x",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.ReturnTo, "/"))
}

// requestReset opens a reset for identifier and returns its result.
func requestReset(t *testing.T, a *Auth, identifier, method string) PasswordResetResult {
	t.Helper()

	res, err := a.RequestPasswordReset(context.Background(), PasswordResetRequest{Credentials: ClientCredentials{ClientID: "spa"}, Identifier: identifier, Method: method})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Status, reset.VerifyPending))
	qt.Assert(t, qt.IsTrue(res.Token != ""))

	return res
}

// confirmReset submits the proof for the reset behind tok.
func confirmReset(a *Auth, tok string, response map[string]any, password string) (LoginResult, error) {
	return a.ResetPassword(context.Background(), PasswordResetConfirmRequest{Token: tok, Response: response, NewPassword: password})
}

func TestPasswordResetRoundTrip(t *testing.T) {
	a, users := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled))

	// An existing session is what the reset is meant to cut off.
	old := loginAs(t, a, alice(""))

	// Unknown identifiers get the same shape over a decoy request.
	decoy := requestReset(t, a, "nobody@example.com", "")
	qt.Check(t, qt.HasLen(users.delivered, 0))
	qt.Check(t, qt.DeepEquals(decoy.Available, []string{"email", "sms"}))
	qt.Check(t, qt.Equals(decoy.Selected, "email"))
	qt.Check(t, qt.Equals(decoy.Interaction, reset.InteractionLink))

	res := requestReset(t, a, "alice@example.com", "")
	qt.Check(t, qt.DeepEquals(res.Available, decoy.Available))
	qt.Check(t, qt.Equals(res.Interaction, decoy.Interaction))
	qt.Check(t, qt.IsNil(res.Data))

	secret := users.awaitDelivery(t)

	// The decoy and a wrong token are refused the same way, whatever the new password.
	_, err := confirmReset(a, decoy.Token, map[string]any{"token": secret}, "brandnew1")
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	_, err = confirmReset(a, res.Token, map[string]any{"token": "not-it"}, "brandnew1")
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	_, err = confirmReset(a, decoy.Token, map[string]any{"token": secret}, "x")
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	_, err = confirmReset(a, res.Token, map[string]any{"token": "not-it"}, "x")
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	done, err := confirmReset(a, res.Token, map[string]any{"token": secret}, "brandnew1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))
	qt.Check(t, qt.IsTrue(done.AccessToken != ""))
	qt.Check(t, qt.Equals(users.passwords["alice"], "brandnew1"))

	// The request is spent and the earlier session is gone.
	_, err = confirmReset(a, res.Token, map[string]any{"token": secret}, "another1")
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	_, _, err = a.IntrospectToken(context.Background(), old.AccessToken)
	qt.Check(t, qt.IsNotNil(err))

	_, _, err = a.IntrospectToken(context.Background(), done.AccessToken)
	qt.Check(t, qt.IsNil(err))
}

func TestPasswordResetCodeMethodAndSwitching(t *testing.T) {
	a, users := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled))

	// Alice has no phone: sms is offered but opens nothing, exactly like a decoy.
	res := requestReset(t, a, "alice", "sms")
	qt.Check(t, qt.Equals(res.Interaction, reset.InteractionCode))
	qt.Check(t, qt.HasLen(users.delivered["u1"], 0))

	_, err := confirmReset(a, res.Token, map[string]any{"code": "000000"}, "brandnew1")
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	// Switching to email opens a real challenge on the same request.
	switched, err := a.BeginPasswordReset(context.Background(), PasswordResetStepRequest{Token: res.Token, Method: "email"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(switched.Selected, "email"))
	qt.Check(t, qt.Equals(switched.Token, res.Token))
	users.awaitDelivery(t)

	// Fresh has a phone: a six-digit code arrives and a wrong one is a failed attempt.
	res = requestReset(t, a, "fresh", "sms")
	code := users.awaitDelivery(t)
	qt.Check(t, qt.HasLen(code, 6))

	_, err = confirmReset(a, res.Token, map[string]any{"code": "000000"}, "brandnew1")
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	done, err := confirmReset(a, res.Token, map[string]any{"code": code}, "brandnew1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))
	qt.Check(t, qt.Equals(users.passwords["fresh"], "brandnew1"))
}

func TestPasswordResetClientRestrictsMethods(t *testing.T) {
	cl := mfaClient(client.MFAPolicyDisabled)
	cl.AllowedPasswordResetMethods = []string{"sms"}
	a, _ := newAccountTestAuth(t, cl)

	res := requestReset(t, a, "fresh", "")
	qt.Check(t, qt.DeepEquals(res.Available, []string{"sms"}))
	qt.Check(t, qt.Equals(res.Selected, "sms"))

	_, err := a.RequestPasswordReset(context.Background(), PasswordResetRequest{Credentials: ClientCredentials{ClientID: "spa"}, Identifier: "fresh", Method: "email"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	_, err = a.BeginPasswordReset(context.Background(), PasswordResetStepRequest{Token: res.Token, Method: "email"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

// approvalMethod is an asynchronous method approved out of band.
type approvalMethod struct {
	mu       sync.Mutex
	approved map[string]bool
}

func (m *approvalMethod) Begin(context.Context, *reset.Request, UserInfo) (string, map[string]any, error) {
	return "challenge", map[string]any{"transaction": "42"}, nil
}

func (m *approvalMethod) Verify(_ context.Context, req *reset.Request, _ UserInfo, _ map[string]any) (reset.VerifyResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ok, decided := m.approved[req.ID]; decided {
		if ok {
			return reset.VerifyApproved, nil
		}

		return reset.VerifyDenied, nil
	}

	return reset.VerifyPending, nil
}

func (m *approvalMethod) Interaction() string { return reset.InteractionPoll }

func TestPasswordResetAsyncMethod(t *testing.T) {
	m := &approvalMethod{approved: map[string]bool{}}
	a, users := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled), PasswordResetRegistry(reset.Methods(map[string]reset.Method{"push": m})))

	res := requestReset(t, a, "alice", "")
	qt.Check(t, qt.Equals(res.Interaction, reset.InteractionPoll))
	qt.Check(t, qt.Equals(res.Data["transaction"], "42"))

	status, err := a.PasswordResetStatus(context.Background(), PasswordResetStepRequest{Token: res.Token})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(status.Status, reset.VerifyPending))

	// Confirming before approval does not spend anything, and a decoy answers the same.
	_, err = confirmReset(a, res.Token, nil, "brandnew1")
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	decoy := requestReset(t, a, "nobody", "")

	_, err = confirmReset(a, decoy.Token, nil, "brandnew1")
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	m.approved[res.Token] = true

	status, err = a.PasswordResetStatus(context.Background(), PasswordResetStepRequest{Token: res.Token})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(status.Status, reset.VerifyApproved))

	done, err := confirmReset(a, res.Token, nil, "brandnew1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))
	qt.Check(t, qt.Equals(users.passwords["alice"], "brandnew1"))

	// A denial spends the request.
	res = requestReset(t, a, "alice", "")
	m.approved[res.Token] = false

	_, err = a.PasswordResetStatus(context.Background(), PasswordResetStepRequest{Token: res.Token})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	_, err = a.PasswordResetStatus(context.Background(), PasswordResetStepRequest{Token: res.Token})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
}

func TestPasswordResetDeliveryRunsInBackground(t *testing.T) {
	a, users := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled))
	users.deliverErr = errors.New("smtp down")

	// The challenge is live before delivery, and a delivery failure is the deliverer's.
	res := requestReset(t, a, "alice", "")
	secret := users.awaitDelivery(t)

	req, err := a.PasswordResets().Get(context.Background(), res.Token)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(req.ChallengeID != ""))

	done, err := confirmReset(a, res.Token, map[string]any{"token": secret}, "brandnew1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))
}

// recordingResets wraps a Store and counts its saves.
type recordingResets struct {
	reset.Store
	saved int
}

func (r *recordingResets) Save(ctx context.Context, t *reset.Request) error {
	r.saved++

	return r.Store.Save(ctx, t)
}

func TestPasswordResetStoreOptionOverridesDefault(t *testing.T) {
	c := cache.New(cache.MemoryCache)
	qt.Assert(t, qt.IsNil(c.Start(context.Background())))
	t.Cleanup(c.Close)

	inner, err := reset.NewCacheStore(c)
	qt.Assert(t, qt.IsNil(err))

	store := &recordingResets{Store: inner}
	a, users := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled), PasswordResetStore(store))
	qt.Check(t, qt.Equals(a.PasswordResets(), reset.Store(store)))

	res := requestReset(t, a, "alice", "")
	qt.Check(t, qt.Equals(store.saved, 1))

	done, err := confirmReset(a, res.Token, map[string]any{"token": users.awaitDelivery(t)}, "brandnew1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))
}

func TestPasswordResetCutsPendingSessions(t *testing.T) {
	a, users := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled))

	// An attacker holding the temporary password is parked at the password step.
	held := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "fresh", Password: "changeme"})
	qt.Assert(t, qt.Equals(held.Status, session.StatusPendingPasswordChange))

	opened := requestReset(t, a, "fresh", "")

	res, err := confirmReset(a, opened.Token, map[string]any{"token": users.awaitDelivery(t)}, "owner123")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))

	// The parked step can no longer set the password.
	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: held.StepToken, NewPassword: "stolen"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))
	qt.Check(t, qt.Equals(users.passwords["fresh"], "owner123"))
}

// plainStore hides the memory store's Lister capability, like the cache-backed store.
type plainStore struct{ session.Store }

func TestPasswordResetDisarmsParkedStepWithoutLister(t *testing.T) {
	cfg := validConfig()

	a, users := newAccountTestAuthWithStore(t, cfg, plainStore{session.NewMemoryStore()}, mfaClient(client.MFAPolicyDisabled))

	held := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "fresh", Password: "changeme"})
	qt.Assert(t, qt.Equals(held.Status, session.StatusPendingPasswordChange))

	opened := requestReset(t, a, "fresh", "")

	_, err := confirmReset(a, opened.Token, map[string]any{"token": users.awaitDelivery(t)}, "owner123")
	qt.Assert(t, qt.IsNil(err))

	// The session survives, but its step no longer applies.
	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: held.StepToken, NewPassword: "stolen"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))
	qt.Check(t, qt.Equals(users.passwords["fresh"], "owner123"))
}

func TestPasswordPolicyGuardsEveryPath(t *testing.T) {
	a, users := newAccountTestAuth(t, registeringClient())

	weak := func(t *testing.T, err error) {
		t.Helper()
		qt.Assert(t, qt.IsNotNil(err))
		qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
		qt.Check(t, qt.IsTrue(errors.Is(err, ErrWeakPassword)))
	}

	_, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "dave", Email: "dave@example.com", Password: "dave2024"})
	weak(t, err)

	res := loginAs(t, a, alice(""))

	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: res.AccessToken, CurrentPassword: "secret123", NewPassword: "short"})
	weak(t, err)
	qt.Check(t, qt.Equals(users.passwords["alice"], "secret123"))

	held := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "fresh", Password: "changeme"})

	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: held.StepToken, NewPassword: "fresh@example.com"})
	weak(t, err)
	qt.Check(t, qt.Equals(users.passwords["fresh"], "changeme"))

	// A rejected password spends neither the request nor its proof.
	opened := requestReset(t, a, "alice", "")
	proof := map[string]any{"token": users.awaitDelivery(t)}

	_, err = confirmReset(a, opened.Token, proof, "tiny")
	weak(t, err)

	done, err := confirmReset(a, opened.Token, proof, "long enough now")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))
}

type denyAllPasswords struct{}

func (denyAllPasswords) Validate(context.Context, string, UserInfo) error {
	return fmt.Errorf("%w: breached", ErrWeakPassword)
}

func TestPasswordPolicyOptionOverridesDefault(t *testing.T) {
	a, _ := newAccountTestAuth(t, registeringClient(), PasswordPolicy(denyAllPasswords{}))

	qt.Check(t, qt.Equals(a.PasswordPolicy(), contract.PasswordPolicy(denyAllPasswords{})))

	_, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "dave", Password: "perfectly fine otherwise"})
	qt.Assert(t, qt.IsNotNil(err))

	var oe *OAuthError
	qt.Assert(t, qt.IsTrue(errors.As(err, &oe)))
	qt.Check(t, qt.Equals(oe.Description, "password does not meet the policy: breached"))
}

func TestProfileRoundTrip(t *testing.T) {
	a, _ := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled))

	res := loginAs(t, a, alice(""))

	data, err := a.Profile(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(data, 0))

	qt.Assert(t, qt.IsNil(a.UpdateProfile(context.Background(), res.AccessToken, map[string]any{"locale": "lv"})))

	data, err = a.Profile(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(data, map[string]any{"locale": "lv"}))

	_, err = a.Profile(context.Background(), res.StepToken)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))
}
