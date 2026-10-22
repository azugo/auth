package auth

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/internal/mfatest"
	"azugo.io/auth/mfa"
	"azugo.io/auth/mfa/recovery"
	"azugo.io/auth/mfa/totp"
	"azugo.io/auth/reset"
	"azugo.io/auth/session"

	"azugo.io/core/cache"
	"github.com/go-quicktest/qt"
)

// newStepUpTestAuth builds an auth whose contact changes need what policy requires.
func newStepUpTestAuth(t *testing.T, policy StepUpPolicy) (*Auth, *accountUsers) {
	t.Helper()

	users := newAccountUsers()

	a, err := New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)),
		MFAStore(mfa.NewMemoryStore()), StepUp(policy))
	qt.Assert(t, qt.IsNil(err))

	return a, users
}

func requireFor(action string, req StepUpRequirement) StepUpPolicy {
	return StepUpPolicyFunc(func(_ context.Context, _ *session.Session, got string) (StepUpRequirement, bool) {
		return req, got == action
	})
}

func addContact(a *Auth, tok string) error {
	_, err := a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "second@example.com"})

	return err
}

func TestStepUpWithMFAOnly(t *testing.T) {
	a, _ := newStepUpTestAuth(t, requireFor(ActionAddContact, StepUpRequirement{MaxAge: 5 * time.Minute, Methods: []string{"otp"}}))

	first := loginAs(t, a, alice("")).AccessToken
	seed := enrollTOTP(t, a, first)

	// A factor enrolled through the session itself cannot re-authenticate it.
	_, err := a.BeginReauth(context.Background(), ReauthRequest{Token: first, Action: ActionAddContact})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnmetAuthenticationRequirements))

	tok := loginAs(t, a, alice("")).AccessToken

	err = addContact(a, tok)
	qt.Assert(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientUserAuthentication))
	qt.Check(t, qt.Equals(err.(*OAuthError).StatusCode(), 401))

	headers := map[string]string{}
	for k, v := range err.(*OAuthError).ErrorHeaders() {
		headers[k] = v
	}

	qt.Check(t, qt.Matches(headers["WWW-Authenticate"], `.*error="insufficient_user_authentication".*max_age=300`))

	// Actions the policy does not name and the library has no default for stay open.
	_, err = a.RequireStepUp(context.Background(), tok, ActionRevokeSession)
	qt.Check(t, qt.IsNil(err))

	// The password is not offered when the policy asks for a second factor.
	res, err := a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: ActionAddContact})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(res.Available, []string{totp.DriverName}))
	qt.Check(t, qt.Equals(res.Interaction, mfa.InteractionCode))

	err = a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Response: map[string]any{"code": "000000"}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	qt.Assert(t, qt.IsNil(a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Response: map[string]any{"code": nextCode(t, seed)}})))
	qt.Check(t, qt.IsNil(addContact(a, tok)))

	// The re-authentication raised the session's methods without a new login.
	_, sess, err := a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(slices.Contains(sess.AuthMethods, "otp")))
	qt.Check(t, qt.IsFalse(slices.Contains(sess.AuthMethods, "pwd")))
	qt.Check(t, qt.IsTrue(slices.Contains(sess.AMR, "otp")))

	// The proof is spent with the re-authentication.
	err = a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Response: map[string]any{"code": nextCode(t, seed)}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

func TestStepUpWithPassword(t *testing.T) {
	a, _ := newStepUpTestAuth(t, requireFor(ActionRemoveContact, StepUpRequirement{MaxAge: 5 * time.Minute, Methods: []string{"pwd"}}))

	tok := loginAs(t, a, alice("")).AccessToken
	remove := func() error {
		return a.RemoveContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "old@example.com"})
	}

	// A login is an authentication too, so a fresh password session already qualifies.
	qt.Check(t, qt.IsNil(remove()))

	// Once the login is older than MaxAge the password is asked again.
	_, sess, err := a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))

	sess.AuthTime = time.Now().Add(-10 * time.Minute)
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), sess)))

	qt.Check(t, qt.Equals(oauthErrorCode(t, remove()), ErrCodeInsufficientUserAuthentication))

	res, err := a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: ActionRemoveContact})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(res.Available, []string{reauthPassword}))

	err = a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Password: "wrong"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	qt.Assert(t, qt.IsNil(a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Password: "secret123"})))
	qt.Check(t, qt.IsNil(remove()))
}

func TestStepUpGuardsContactManagement(t *testing.T) {
	a, _ := newStepUpTestAuth(t, StepUpPolicyFunc(func(_ context.Context, _ *session.Session, _ string) (StepUpRequirement, bool) {
		return StepUpRequirement{Methods: []string{"otp"}}, true
	}))

	tok := loginAs(t, a, alice("")).AccessToken
	change := ContactRequest{Token: tok, Channel: ChannelEmail, Address: "alice@example.com"}

	qt.Check(t, qt.Equals(oauthErrorCode(t, addContact(a, tok)), ErrCodeInsufficientUserAuthentication))
	qt.Check(t, qt.Equals(oauthErrorCode(t, a.SetPrimaryContact(context.Background(), change)), ErrCodeInsufficientUserAuthentication))
	qt.Check(t, qt.Equals(oauthErrorCode(t, a.RemoveContact(context.Background(), change)), ErrCodeInsufficientUserAuthentication))

	// Without an earlier factor nothing can satisfy the policy.
	_, err := a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: ActionRemoveContact})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnmetAuthenticationRequirements))
}

func TestStepUpGuardsEverySensitiveAction(t *testing.T) {
	users := newAccountUsers()

	a, err := New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()), MFAStore(mfa.NewMemoryStore()), LoginSteps(&tenantStep{tenants: []string{"acme", "globex"}}),
		StepUp(StepUpPolicyFunc(func(_ context.Context, _ *session.Session, action string) (StepUpRequirement, bool) {
			return StepUpRequirement{Methods: []string{"otp"}}, action != "public.read"
		})))
	qt.Assert(t, qt.IsNil(err))

	pending := loginAs(t, a, alice(""))
	tok := resolveStep(t, a, pending, "tenant", `{"tenant":"acme"}`).AccessToken

	refused := func(name string, err error) {
		t.Helper()
		qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientUserAuthentication), qt.Commentf(name))
	}

	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: tok, CurrentPassword: "secret123", NewPassword: "another-pass-123"})
	refused("change password", err)
	qt.Check(t, qt.Equals(users.passwords["alice"], "secret123"))

	refused("update profile", a.UpdateProfile(context.Background(), tok, map[string]any{"theme": "dark"}))

	_, err = a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: tok, Method: totp.DriverName})
	refused("enroll mfa", err)

	_, err = a.SwitchSession(context.Background(), SwitchSessionRequest{Token: tok, Selection: map[string]any{"tenant": "globex"}})
	refused("switch session", err)

	_, err = a.RequireStepUp(context.Background(), tok, ActionRevokeSession)
	refused("revoke session", err)

	_, err = a.RequireStepUp(context.Background(), tok, "account.delete")
	refused("app action", err)

	info, err := a.RequireStepUp(context.Background(), tok, "public.read")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.ID, "u1"))
}

func TestMFAMethodCannotTakeThePasswordName(t *testing.T) {
	cfg := validConfig()
	cfg.MFAMethods = []MFAMethodConfig{{Name: reauthPassword, Driver: totp.DriverName}}

	_, err := New(newApp(t), cfg, fakeUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry(), MFAStore(mfa.NewMemoryStore()))
	qt.Check(t, qt.ErrorMatches(err, `mfa method name "password" is reserved.*`))
}

func TestStepUpACRNeedsAFreshFactor(t *testing.T) {
	users := newAccountUsers()
	store := mfa.NewMemoryStore()

	cfg := validConfig()
	cfg.ACRLevels = acrLadder()

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)),
		MFAStore(store), StepUp(requireFor(ActionAddContact, StepUpRequirement{ACR: "loa2", MaxAge: 5 * time.Minute})))
	qt.Assert(t, qt.IsNil(err))

	seed := enrollTOTP(t, a, loginAs(t, a, alice("")).AccessToken)

	// The factor dates from a day ago.
	enrollments, err := store.List(context.Background(), "u1")
	qt.Assert(t, qt.IsNil(err))

	enrollments[0].CreatedAt = time.Now().Add(-24 * time.Hour)
	qt.Assert(t, qt.IsNil(store.Enroll(context.Background(), enrollments[0])))

	// A session whose second factor was hours ago.
	tok := loginAs(t, a, alice("")).AccessToken

	_, sess, err := a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))

	sess.ACR, sess.AuthACR, sess.MFAMethod = "loa2", "loa2", totp.DriverName
	sess.AuthTime = time.Now().Add(-10 * time.Hour)
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), sess)))

	qt.Check(t, qt.Equals(oauthErrorCode(t, addContact(a, tok)), ErrCodeInsufficientUserAuthentication))

	// The password alone cannot reach loa2, so only the factor is offered.
	res, err := a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: ActionAddContact})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(res.Available, []string{totp.DriverName}))

	qt.Assert(t, qt.IsNil(a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Response: map[string]any{"code": nextCode(t, seed)}})))
	qt.Check(t, qt.IsNil(addContact(a, tok)))
}

func TestPasswordReauthDoesNotKeepAnOldLevel(t *testing.T) {
	cfg := validConfig()
	cfg.ACRLevels = acrLadder()

	users := newAccountUsers()

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()), StepUp(requireFor("account.delete", StepUpRequirement{MaxAge: time.Minute})))
	qt.Assert(t, qt.IsNil(err))

	tok := loginAs(t, a, alice("")).AccessToken

	_, sess, err := a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))

	sess.ACR = "loa2"
	sess.AuthACR = "loa2"
	sess.MFAMethod = totp.DriverName
	sess.AuthTime = time.Now().Add(-time.Hour)
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), sess)))

	_, err = a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: "account.delete"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Password: "secret123"})))

	// The session keeps its level, but the latest authentication only reached loa1.
	_, sess, err = a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.ACR, "loa2"))
	qt.Check(t, qt.Equals(sess.AuthACR, "loa1"))
}

// mfaSession signs alice in on a and marks the session as having passed MFA, the factor last
// proven at proven.
func mfaSession(t *testing.T, a *Auth, proven time.Time, fresh bool) string {
	t.Helper()

	tok := loginAs(t, a, alice("")).AccessToken

	_, sess, err := a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))

	sess.MFAMethod = totp.DriverName
	sess.AuthMFA = fresh
	sess.AuthTime = proven
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), sess)))

	return tok
}

func TestChangingExistingFactorsNeedsAFreshFactorByDefault(t *testing.T) {
	store := mfa.NewMemoryStore()

	// The account had a factor before any of the sessions below.
	seeded := newMFATestAuth(t, mfaClient(client.MFAPolicyDisabled), store)
	enrollTOTP(t, seeded, loginAs(t, seeded, alice("")).AccessToken)

	a := newMFATestAuth(t, mfaClient(client.MFAPolicyDisabled), store)
	qt.Check(t, qt.IsTrue(a.StepUpEnabled()))

	// A second factor passed hours ago, or only the password since, is not enough.
	stale := mfaSession(t, a, time.Now().Add(-time.Hour), true)

	_, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: stale, Method: recovery.DriverName})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientUserAuthentication))
	qt.Check(t, qt.Equals(oauthErrorCode(t, a.RevokeMFA(context.Background(), stale, totp.DriverName)), ErrCodeInsufficientUserAuthentication))

	passwordOnly := mfaSession(t, a, time.Now(), false)

	_, err = a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: passwordOnly, Method: recovery.DriverName})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientUserAuthentication))

	// Only a second factor can re-authenticate for it.
	res, err := a.BeginReauth(context.Background(), ReauthRequest{Token: passwordOnly, Action: ActionEnrollMFA})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(slices.Contains(res.Available, reauthPassword)))

	// A fresh second factor passes.
	fresh := mfaSession(t, a, time.Now(), true)

	_, err = a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: fresh, Method: recovery.DriverName})
	qt.Check(t, qt.IsNil(err))
}

func TestNoStepUpRelaxesTheDefault(t *testing.T) {
	store := mfa.NewMemoryStore()

	seeded := newMFATestAuth(t, mfaClient(client.MFAPolicyDisabled), store)
	enrollTOTP(t, seeded, loginAs(t, seeded, alice("")).AccessToken)

	a := newMFATestAuth(t, mfaClient(client.MFAPolicyDisabled), store, StepUp(requireFor(ActionEnrollMFA, NoStepUp)))

	stale := mfaSession(t, a, time.Now().Add(-time.Hour), true)

	_, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: stale, Method: recovery.DriverName})
	qt.Check(t, qt.IsNil(err))

	// Actions the policy leaves alone keep the default.
	qt.Check(t, qt.Equals(oauthErrorCode(t, a.RevokeMFA(context.Background(), stale, totp.DriverName)), ErrCodeInsufficientUserAuthentication))
}

func TestFirstFactorNeedsARecentAuthenticationByDefault(t *testing.T) {
	a, _ := newStepUpTestAuth(t, nil)

	tok := loginAs(t, a, alice(""))

	// A session long after its login cannot enrol the account's first factor.
	_, sess, err := a.IntrospectToken(context.Background(), tok.AccessToken)
	qt.Assert(t, qt.IsNil(err))

	sess.AuthTime = time.Now().Add(-time.Hour)
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), sess)))

	_, err = a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: tok.AccessToken, Method: totp.DriverName})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientUserAuthentication))

	// The password proves it is the owner.
	res, err := a.BeginReauth(context.Background(), ReauthRequest{Token: tok.AccessToken, Action: ActionEnrollMFA})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(res.Available, []string{reauthPassword}))
	qt.Assert(t, qt.IsNil(a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok.AccessToken, Password: "secret123"})))

	enrollTOTP(t, a, tok.AccessToken)
}

func TestContactChangesNeedARecentAuthenticationByDefault(t *testing.T) {
	a, _ := newStepUpTestAuth(t, nil)

	tok := loginAs(t, a, alice("")).AccessToken
	qt.Check(t, qt.IsNil(addContact(a, tok)))

	// A session long after its login cannot change the account's contacts.
	_, sess, err := a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))

	sess.AuthTime = time.Now().Add(-time.Hour)
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), sess)))

	change := ContactRequest{Token: tok, Channel: ChannelEmail, Address: "alice@example.com"}

	qt.Check(t, qt.Equals(oauthErrorCode(t, addContact(a, tok)), ErrCodeInsufficientUserAuthentication))
	qt.Check(t, qt.Equals(oauthErrorCode(t, a.SetPrimaryContact(context.Background(), change)), ErrCodeInsufficientUserAuthentication))
	qt.Check(t, qt.Equals(oauthErrorCode(t, a.RemoveContact(context.Background(), change)), ErrCodeInsufficientUserAuthentication))

	// The password proves it is the owner.
	res, err := a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: ActionAddContact})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(res.Available, []string{reauthPassword}))
	qt.Assert(t, qt.IsNil(a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Password: "secret123"})))

	_, err = a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "third@example.com"})
	qt.Check(t, qt.IsNil(err))
}

func TestContactChangesNeedAFreshFactorByDefault(t *testing.T) {
	a, _ := newStepUpTestAuth(t, nil)

	seed := enrollTOTP(t, a, loginAs(t, a, alice("")).AccessToken)

	// With a factor from before the session, the password alone is not enough.
	tok := loginAs(t, a, alice("")).AccessToken
	qt.Check(t, qt.Equals(oauthErrorCode(t, addContact(a, tok)), ErrCodeInsufficientUserAuthentication))

	res, err := a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: ActionAddContact})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(res.Available, []string{totp.DriverName}))
	qt.Assert(t, qt.IsNil(a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Response: map[string]any{"code": nextCode(t, seed)}})))

	qt.Check(t, qt.IsNil(addContact(a, tok)))
}

func TestNoStepUpRelaxesTheContactDefault(t *testing.T) {
	a, _ := newStepUpTestAuth(t, requireFor(ActionAddContact, NoStepUp))

	tok := loginAs(t, a, alice("")).AccessToken

	_, sess, err := a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))

	sess.AuthTime = time.Now().Add(-time.Hour)
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), sess)))

	qt.Check(t, qt.IsNil(addContact(a, tok)))

	// Actions the policy leaves alone keep the default.
	err = a.RemoveContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "alice@example.com"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientUserAuthentication))
}

func TestContactVerificationEnablesStepUp(t *testing.T) {
	users := newVerificationUsers()

	a, err := New(newApp(t), validConfig(), fakeUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(a.StepUpEnabled()))

	a, err = New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(a.StepUpEnabled()))
}

func TestReauthNeedsTheApprovingEnrollment(t *testing.T) {
	store := mfa.NewMemoryStore()
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyDisabled), store, StepUp(requireFor("account.delete", StepUpRequirement{MFA: true})))

	first := loginAs(t, a, alice("")).AccessToken

	_, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: first, Method: mfatest.DriverName})
	qt.Assert(t, qt.IsNil(err))
	_, err = a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: first, Method: mfatest.DriverName, Response: map[string]any{"device": "phone-1"}})
	qt.Assert(t, qt.IsNil(err))

	tok := loginAs(t, a, alice("")).AccessToken

	res, err := a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: "account.delete", Method: mfatest.DriverName})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(res.Selected, mfatest.DriverName))

	a.Config().Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 1, Window: time.Minute, LockoutTTL: time.Minute}

	// An approval that does not say which device answered cannot prove the factor is old.
	approvePush(t, a, "u1")

	err = a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnmetAuthenticationRequirements))

	// It was no wrong guess, so the one allowed attempt is still there.
	qt.Check(t, qt.IsNil(a.checkThrottle(context.Background(), []string{"mfa:u1"}, "", "")))

	_, err = a.RequireStepUp(context.Background(), tok, "account.delete")
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientUserAuthentication))
}

// listCountingStore is an MFA store that counts List calls.
type listCountingStore struct {
	mfa.Store

	lists *atomic.Int32
}

func (s listCountingStore) List(ctx context.Context, userID string) ([]*mfa.Enrollment, error) {
	s.lists.Add(1)

	return s.Store.List(ctx, userID)
}

func TestLoginWithoutMFALoadsNoFactors(t *testing.T) {
	for _, policy := range []client.MFAPolicy{client.MFAPolicyDisabled, client.MFAPolicyOptional} {
		lists := &atomic.Int32{}
		a := newMFATestAuth(t, mfaClient(policy), listCountingStore{Store: mfa.NewMemoryStore(), lists: lists})

		loginAs(t, a, alice(""))

		// Only a client or level that can ask for a factor looks the factors up.
		qt.Check(t, qt.Equals(lists.Load() > 0, policy == client.MFAPolicyOptional), qt.Commentf("policy %q", policy))
	}
}

func TestBeginReauthListsEnrollmentsOnce(t *testing.T) {
	lists := &atomic.Int32{}
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyDisabled), listCountingStore{Store: mfa.NewMemoryStore(), lists: lists})

	enrollTOTP(t, a, loginAs(t, a, alice("")).AccessToken)
	tok := loginAs(t, a, alice("")).AccessToken

	lists.Store(0)

	res, err := a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: ActionRevokeMFA})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(res.Available, []string{totp.DriverName}))
	qt.Check(t, qt.Equals(lists.Load(), int32(1)))
}

func TestReauthReachesOnlyTheLevelItProves(t *testing.T) {
	policy := StepUpPolicyFunc(func(_ context.Context, _ *session.Session, action string) (StepUpRequirement, bool) {
		switch action {
		case "account.delete":
			return StepUpRequirement{ACR: "high"}, true
		case "account.read":
			return StepUpRequirement{ACR: "low", MaxAge: time.Minute}, true
		}

		return StepUpRequirement{}, false
	})

	a, _ := newStepUpTestAuth(t, policy)
	a.Config().ACRLevels = []contract.ACRLevelConfig{
		{Value: "low", Level: 1, AuthMethods: []string{client.AuthMethodPassword}},
		{Value: "high", Level: 2, AuthMethods: []string{"corp"}},
	}

	// The session was opened by the corp IdP.
	tok := loginAs(t, a, alice("")).AccessToken

	_, sess, err := a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))

	sess.AuthProvider = "corp"
	sess.AuthTime = time.Now().Add(-time.Hour)
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), sess)))

	// The password does not prove the corp login again.
	_, err = a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: "account.delete"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnmetAuthenticationRequirements))

	_, err = a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: "account.read"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Password: "secret123"})))

	_, sess, err = a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.AuthACR, "low"))
}

func TestReauthWithPasswordAndFactorReachesTheirLevel(t *testing.T) {
	a, _ := newStepUpTestAuth(t, requireFor("account.delete", StepUpRequirement{ACR: "high"}))
	a.Config().ACRLevels = []contract.ACRLevelConfig{
		{Value: "low", Level: 1, AuthMethods: []string{client.AuthMethodPassword}},
		{Value: "high", Level: 2, AuthMethods: []string{client.AuthMethodPassword}, RequireMFA: true},
	}

	seed := enrollTOTP(t, a, loginAs(t, a, alice("")).AccessToken)
	tok := loginAs(t, a, alice("")).AccessToken

	// Neither the password nor the factor reaches the level alone, so the factor asks for both.
	res, err := a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: "account.delete"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(res.Available, []string{totp.DriverName}))
	qt.Check(t, qt.IsTrue(res.Password))

	code := nextCode(t, seed)

	err = a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Response: map[string]any{"code": code}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	qt.Assert(t, qt.IsNil(a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Password: "secret123", Response: map[string]any{"code": code}})))

	_, err = a.RequireStepUp(context.Background(), tok, "account.delete")
	qt.Check(t, qt.IsNil(err))
}

func TestNeedlessReauthIsRefused(t *testing.T) {
	a, _ := newStepUpTestAuth(t, requireFor("account.delete", StepUpRequirement{MaxAge: time.Hour}))

	tok := loginAs(t, a, alice("")).AccessToken

	// Neither an action without a requirement nor one the session already meets re-authenticates.
	for _, action := range []string{"", "account.delete"} {
		_, err := a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: action})
		qt.Check(t, qt.ErrorMatches(err, "invalid_request: re-authentication is not needed"))
	}
}

// ttlLessCache is a cache that cannot report a key's remaining lifetime.
type ttlLessCache[T any] struct {
	cache.Instance[T]
}

func (ttlLessCache[T]) TTL(context.Context, string) (time.Duration, bool, error) {
	return 0, false, nil
}

func TestPollingAPushFactorNeedsThePasswordOnce(t *testing.T) {
	for _, ttlLess := range []bool{false, true} {
		store := mfa.NewMemoryStore()
		a := newMFATestAuth(t, mfaClient(client.MFAPolicyDisabled), store, StepUp(requireFor("account.delete", StepUpRequirement{ACR: "high"})))
		a.Config().ACRLevels = []contract.ACRLevelConfig{
			{Value: "low", Level: 1, AuthMethods: []string{client.AuthMethodPassword}},
			{Value: "high", Level: 2, AuthMethods: []string{client.AuthMethodPassword}, RequireMFA: true},
		}

		first := loginAs(t, a, alice("")).AccessToken

		_, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: first, Method: mfatest.DriverName})
		qt.Assert(t, qt.IsNil(err))
		_, err = a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: first, Method: mfatest.DriverName, Response: map[string]any{"device": "phone-1"}})
		qt.Assert(t, qt.IsNil(err))

		// A cache that cannot tell the remaining lifetime keeps the proven password too.
		if ttlLess {
			a.reauths = ttlLessCache[reauthState]{a.reauths}
		}

		tok := loginAs(t, a, alice("")).AccessToken
		a.Config().Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

		res, err := a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: "account.delete", Method: mfatest.DriverName})
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsTrue(res.Password))

		err = a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Password: "secret123"})
		qt.Check(t, qt.ErrorMatches(err, ".*awaiting approval"))

		// Polls carry no password, and none of them counts as a wrong one.
		for range 3 {
			err = a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok})
			qt.Check(t, qt.ErrorMatches(err, ".*awaiting approval"))
		}

		qt.Check(t, qt.IsNil(a.checkThrottle(context.Background(), []string{"pwdchange:u1"}, "", "")))
	}
}

func TestEnrolmentFinishesUnderTheStepUpItBeganWith(t *testing.T) {
	a, _ := newStepUpTestAuth(t, nil)

	tok := loginAs(t, a, alice("")).AccessToken
	other := loginAs(t, a, alice("")).AccessToken

	data, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: tok, Method: totp.DriverName})
	qt.Assert(t, qt.IsNil(err))

	seed, _ := data["secret"].(string)
	code, err := totp.GenerateCode(seed, time.Now())
	qt.Assert(t, qt.IsNil(err))

	// The user takes long enough to scan the code that the step-up window has passed.
	_, sess, err := a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))

	sess.AuthTime = time.Now().Add(-time.Hour)
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), sess)))

	// Another session of the same user cannot finish it.
	_, err = a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: other, Method: totp.DriverName, Response: map[string]any{"code": code}})
	qt.Check(t, qt.ErrorMatches(err, "invalid_request: no mfa enrollment in progress"))

	_, err = a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: tok, Method: totp.DriverName, Response: map[string]any{"code": code}})
	qt.Check(t, qt.IsNil(err))
}

func TestReauthReleasesTheChallengeBudget(t *testing.T) {
	a, _ := newStepUpTestAuth(t, requireFor("account.delete", StepUpRequirement{MFA: true}))

	seed := enrollTOTP(t, a, loginAs(t, a, alice("")).AccessToken)
	tok := loginAs(t, a, alice("")).AccessToken

	// Earlier challenges used most of the user's budget for issuing more.
	a.Config().Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 3, Window: time.Minute, LockoutTTL: time.Minute}

	for range 2 {
		qt.Assert(t, qt.IsNil(a.checkThrottle(context.Background(), []string{"mfa-open:u1"}, "", "")))
		a.failThrottle(context.Background(), []string{"mfa-open:u1"})
	}

	_, err := a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: "account.delete"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Response: map[string]any{"code": nextCode(t, seed)}})))

	// A passed factor releases it, as at login.
	for range 2 {
		qt.Check(t, qt.IsNil(a.checkThrottle(context.Background(), []string{"mfa-open:u1"}, "", "")))
	}
}

func TestFactorEnrolledInASessionNeverCountsInIt(t *testing.T) {
	a, _ := newStepUpTestAuth(t, StepUpPolicyFunc(func(_ context.Context, _ *session.Session, action string) (StepUpRequirement, bool) {
		switch action {
		case ActionAddContact:
			return StepUpRequirement{Methods: []string{"otp"}}, true
		case "account.read":
			return StepUpRequirement{MaxAge: time.Minute}, true
		}

		return StepUpRequirement{}, false
	}))

	tok := loginAs(t, a, alice("")).AccessToken
	enrollTOTP(t, a, tok)

	_, sess, err := a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))

	sess.AuthTime = time.Now().Add(-time.Hour)
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), sess)))

	// A password re-authentication moves the session's last authentication past the enrolment.
	_, err = a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: "account.read"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Password: "secret123"})))

	// The factor still dates from within the session, so it cannot satisfy the step-up.
	_, err = a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: ActionAddContact})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnmetAuthenticationRequirements))
}

func TestIntrospectionIgnoresFactorEnrolledInTheSession(t *testing.T) {
	a, _ := newStepUpTestAuth(t, nil)

	tok := loginAs(t, a, alice("")).AccessToken
	enrollTOTP(t, a, tok)

	info, sess, err := a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.SliceContains(sess.AMR, "otp"))
	qt.Check(t, qt.Equals(info.ACR, sess.AuthACR))
	qt.Check(t, qt.Not(qt.SliceContains(info.AMR, "otp")))
}
