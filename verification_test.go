package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/contact"
	"azugo.io/auth/contract"
	"azugo.io/auth/mfa"
	"azugo.io/auth/reset"
	"azugo.io/auth/session"

	"azugo.io/core/http"
	"github.com/go-quicktest/qt"
)

const stepVerifyEmail = "verify_email"

// newVerificationUsers returns the account users with every contact still unverified.
func newVerificationUsers() *accountUsers {
	users := newAccountUsers()

	for name, u := range users.users {
		for channel, contacts := range u.Contacts {
			for i := range contacts {
				contacts[i].Verified = false
			}

			u.Contacts[channel] = contacts
		}

		users.users[name] = u
	}

	return users
}

func newVerificationTestAuth(t *testing.T, cl *client.Client, link bool) (*Auth, *accountUsers) {
	t.Helper()

	users := newVerificationUsers()
	users.claimable[ChannelEmail] = true

	method := reset.Code(users.deliver("email"), 6)
	if link {
		method = reset.Link(users.deliver("email"))
	}

	a, err := New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(cl),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, method), LoginSteps(newAgreementStep("v1")))
	qt.Assert(t, qt.IsNil(err))

	return a, users
}

func (f *accountUsers) user(name string) UserInfo {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.users[name]
}

func (f *accountUsers) lastRequest(userID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.requests[userID]
}

func TestEmailVerificationHoldsLoginUntilCodePresented(t *testing.T) {
	a, users := newVerificationTestAuth(t, mfaClient(client.MFAPolicyDisabled), false)

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Status, session.StatusPendingStep))
	qt.Check(t, qt.Equals(pending.Step, stepVerifyEmail))
	qt.Check(t, qt.Equals(pending.Interaction, reset.InteractionCode))

	first := users.awaitDelivery(t)

	retry := resolveStep(t, a, pending, stepVerifyEmail, `{"code":"000000x"}`)
	qt.Check(t, qt.Equals(retry.Status, session.StatusPendingStep))
	qt.Check(t, qt.Equals(retry.Data["error"], any("invalid_response")))

	// A resend replaces the delivered code.
	resent := resolveStep(t, a, pending, stepVerifyEmail, `{"resend":true}`)
	qt.Check(t, qt.Equals(resent.Data["resent"], any(true)))

	second := users.awaitDelivery(t)

	stale := resolveStep(t, a, pending, stepVerifyEmail, `{"code":"`+first+`"}`)
	qt.Check(t, qt.Equals(stale.Status, session.StatusPendingStep))

	// Verification is the first gate, the application's steps follow.
	next := resolveStep(t, a, pending, stepVerifyEmail, "code="+second)
	qt.Assert(t, qt.Equals(next.Status, session.StatusPendingStep))
	qt.Check(t, qt.Equals(next.Step, "agreement"))
	qt.Check(t, qt.IsTrue(users.user("alice").Contacts[ChannelEmail][0].Verified))
}

func TestContactGatedLoginKeepsItsLevel(t *testing.T) {
	users := newVerificationUsers()

	a, err := New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)),
		StepUp(requireFor("account.delete", StepUpRequirement{ACR: "low"})))
	qt.Assert(t, qt.IsNil(err))

	a.Config().ACRLevels = []contract.ACRLevelConfig{{Value: "low", Level: 1, AuthMethods: []string{client.AuthMethodPassword}}}

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Step, stepVerifyEmail))

	res := resolveStep(t, a, pending, stepVerifyEmail, `{"code":"`+users.awaitDelivery(t)+`"}`)
	qt.Assert(t, qt.Equals(res.Status, session.StatusActive))

	// The login that was just completed meets the level it reached.
	_, err = a.RequireStepUp(context.Background(), res.AccessToken, "account.delete")
	qt.Check(t, qt.IsNil(err))
}

// oddMethod is a verification method that answers neither approved, denied nor pending.
type oddMethod struct{}

func (oddMethod) Begin(context.Context, *reset.Request, UserInfo) (string, map[string]any, error) {
	return "challenge", nil, nil
}

func (oddMethod) Verify(context.Context, *reset.Request, UserInfo, map[string]any) (reset.VerifyResult, error) {
	return "", nil
}

func TestVerifyContactRefusesAnUnexpectedResult(t *testing.T) {
	users := newVerificationUsers()

	a, err := New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, oddMethod{}))
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.Equals(loginAs(t, a, alice("")).Step, stepVerifyEmail))

	req, err := a.verifications.Open(context.Background(), ChannelEmail, "u1", "alice@example.com")
	qt.Assert(t, qt.IsNil(err))

	err = a.VerifyContact(context.Background(), ContactVerificationRequest{Request: req.ID, Response: map[string]any{}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
	qt.Check(t, qt.IsFalse(users.user("alice").Contacts[ChannelEmail][0].Verified))
}

func TestVerifyEmailOutsideLogin(t *testing.T) {
	a, users := newVerificationTestAuth(t, mfaClient(client.MFAPolicyDisabled), true)

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Step, stepVerifyEmail))
	qt.Check(t, qt.Equals(pending.Interaction, reset.InteractionLink))

	secret := users.awaitDelivery(t)
	request := users.lastRequest("u1")

	err := a.VerifyContact(context.Background(), ContactVerificationRequest{Request: request, Response: map[string]any{"token": "wrong"}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	err = a.VerifyContact(context.Background(), ContactVerificationRequest{Request: request, Response: map[string]any{"token": secret}})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(users.user("alice").Contacts[ChannelEmail][0].Verified))

	// Single use.
	err = a.VerifyContact(context.Background(), ContactVerificationRequest{Request: request, Response: map[string]any{"token": secret}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	// The parked login moves on without a proof once the address is verified.
	next := resolveStep(t, a, pending, stepVerifyEmail, `{}`)
	qt.Check(t, qt.Equals(next.Step, "agreement"))
}

func TestVerifyContactKeepsProofOnProviderFailure(t *testing.T) {
	a, users := newVerificationTestAuth(t, mfaClient(client.MFAPolicyDisabled), true)

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Step, stepVerifyEmail))

	secret := users.awaitDelivery(t)
	request := users.lastRequest("u1")

	users.mu.Lock()
	users.verifyErr = errors.New("database down")
	users.mu.Unlock()

	err := a.VerifyContact(context.Background(), ContactVerificationRequest{Request: request, Response: map[string]any{"token": secret}})
	qt.Check(t, qt.IsNotNil(err))
	qt.Check(t, qt.IsFalse(users.user("alice").Contacts[ChannelEmail][0].Verified))

	users.mu.Lock()
	users.verifyErr = nil
	users.mu.Unlock()

	// The same proof succeeds once the provider recovers.
	err = a.VerifyContact(context.Background(), ContactVerificationRequest{Request: request, Response: map[string]any{"token": secret}})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(users.user("alice").Contacts[ChannelEmail][0].Verified))
}

// uniform checks a registration answer carries a request handle and drops it, as it differs per
// registration.
func uniform(t *testing.T, res RegisterResult) RegisterResult {
	t.Helper()

	qt.Check(t, qt.IsTrue(res.Request != ""))

	res.Request = ""

	return res
}

func TestRegistrationAnswersUniformlyWithEmailVerification(t *testing.T) {
	a, users := newVerificationTestAuth(t, registeringClient(), false)

	// Only an account with a verified address is told about a repeated registration.
	users.setContacts("alice", ChannelEmail, Contact{Address: "alice@example.com", Verified: true})

	reg, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Contacts: map[string]string{ChannelEmail: "bob@example.com"}, Password: "pw123456"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(uniform(t, reg), RegisterResult{Accepted: true, Interaction: reset.InteractionCode}))

	users.awaitDelivery(t)
	qt.Check(t, qt.Equals(len(users.delivered["u-bob"]), 1))

	// A taken identifier answers alike and mails the owner a password reset.
	// A taken username is public, so it is answered openly whatever the address.
	_, err = a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Contacts: map[string]string{ChannelEmail: "new@example.com"}, Password: "pw123456"})
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrUsernameTaken)))

	taken, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice2", Contacts: map[string]string{ChannelEmail: "alice@example.com"}, Password: "pw123456"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(uniform(t, taken), uniform(t, reg)))

	users.awaitDelivery(t)

	users.mu.Lock()
	qt.Check(t, qt.DeepEquals(users.registrationMails, []string{"u1"}))
	users.mu.Unlock()

	// Without an address on a verified channel the registration answers as usual.
	plain, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "eve", Password: "pw123456"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(plain.Accepted))
	qt.Check(t, qt.Equals(plain.UserID, "u-eve"))
}

func TestOwnerClaimsASquattedAddress(t *testing.T) {
	a, users := newVerificationTestAuth(t, registeringClient(), false)

	register := func(username string) (string, string) {
		reg, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: username, Contacts: map[string]string{ChannelEmail: "victim@example.com"}, Password: "pw123456"})
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsTrue(reg.Accepted))

		// The request ID is recorded by the delivery, so it is read once that has happened.
		code := users.awaitDelivery(t)

		return users.lastRequest("u-" + username), code
	}

	// An unverified squatter does not block the owner, who gets a code of their own.
	squatted, squatterCode := register("mallory")
	owned, ownerCode := register("victim")

	err := a.VerifyContact(context.Background(), ContactVerificationRequest{Request: owned, Response: map[string]any{"code": ownerCode}})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(users.user("victim").Contacts[ChannelEmail][0].Verified))
	qt.Check(t, qt.HasLen(users.user("mallory").Contacts[ChannelEmail], 0))

	// The address is now taken, even with the squatter's own proof.
	err = a.VerifyContact(context.Background(), ContactVerificationRequest{Request: squatted, Response: map[string]any{"code": squatterCode}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
	qt.Check(t, qt.Equals(err.(*OAuthError).StatusCode(), http.StatusConflict))
	qt.Check(t, qt.HasLen(users.user("mallory").Contacts[ChannelEmail], 0))

	// A lost race is final, so the proof is not kept for a retry.
	err = a.VerifyContact(context.Background(), ContactVerificationRequest{Request: squatted, Response: map[string]any{"code": squatterCode}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
}

func TestResetMailsAreCappedPerAccount(t *testing.T) {
	users := newVerificationUsers()
	users.claimable[ChannelEmail] = true
	users.setContacts("alice", ChannelEmail, Contact{Address: "alice@example.com", Verified: true, Primary: true})

	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(registeringClient()),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)))
	qt.Assert(t, qt.IsNil(err))

	// Registrations naming the address spend their own budget, not the owner's resets.
	for _, username := range []string{"alice2", "alice3"} {
		reg, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: username, Contacts: map[string]string{ChannelEmail: "alice@example.com"}, Password: "pw123456"})
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.IsTrue(reg.Accepted))
		users.awaitDelivery(t)
	}

	// Every way of asking for a reset counts against the same mailbox.
	requestReset(t, a, "alice", "email")
	requestReset(t, a, "alice@example.com", "email")
	users.awaitDelivery(t)
	users.awaitDelivery(t)

	// The third is refused silently, answered like the others.
	res := requestReset(t, a, "alice", "email")
	qt.Check(t, qt.Equals(res.Status, reset.VerifyPending))

	users.mu.Lock()
	defer users.mu.Unlock()

	qt.Check(t, qt.HasLen(users.delivered["u1"], 4))
	qt.Check(t, qt.HasLen(users.registrationMails, 2))
}

func TestRegistrationHandleVerifiesWithoutLogin(t *testing.T) {
	users := newVerificationUsers()
	users.claimable[ChannelEmail] = true
	users.setContacts("alice", ChannelEmail, Contact{Address: "alice@example.com", Verified: true})

	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(registeringClient()),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)))
	qt.Assert(t, qt.IsNil(err))

	register := func(username, address string) RegisterResult {
		reg, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: username, Contacts: map[string]string{ChannelEmail: address}, Password: "pw123456"})
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsTrue(reg.Accepted))

		return reg
	}

	// A new account presents the mailed code with the handle it was answered.
	fresh := register("bob", "bob@example.com")
	code := users.awaitDelivery(t)

	qt.Assert(t, qt.IsNil(a.VerifyContact(context.Background(), ContactVerificationRequest{Request: fresh.Request, Response: map[string]any{"code": code}, IP: "192.0.2.1"})))
	qt.Check(t, qt.IsTrue(users.user("bob").Contacts[ChannelEmail][0].Verified))

	// A repeated registration gets a decoy that answers and locks out like a real request.
	created := register("carol", "carol@example.com")
	users.awaitDelivery(t)

	decoy := register("alice2", "alice@example.com")
	users.awaitDelivery(t)

	for i, handle := range []string{created.Request, decoy.Request} {
		var errs []string

		// Every guess comes from a new address, so only the handle's own limit applies.
		for j := range 3 {
			err := a.VerifyContact(context.Background(), ContactVerificationRequest{Request: handle, Response: map[string]any{"code": "000000x"}, IP: fmt.Sprintf("192.0.2.%d", 10+3*i+j)})
			errs = append(errs, err.Error())
		}

		qt.Check(t, qt.DeepEquals(errs, []string{
			"invalid_grant: invalid or expired verification request",
			"invalid_grant: invalid or expired verification request",
			"slow_down: too many attempts",
		}), qt.Commentf("handle %d", i))
	}
}

func TestRegistrationAnswersUniformlyOnPhoneChannel(t *testing.T) {
	users := newVerificationUsers()

	a, err := New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(registeringClient()),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelPhone, reset.Code(users.deliver("sms"), 6)))
	qt.Assert(t, qt.IsNil(err))

	users.setContacts("fresh", ChannelPhone, Contact{Address: "+37120000000", Verified: true})

	// The phone already belongs to fresh, who is told through a reset method that can reach them.
	taken, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "fresh2", Contacts: map[string]string{ChannelPhone: "+37120000000"}, Password: "pw123456"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(uniform(t, taken), RegisterResult{Accepted: true, Interaction: reset.InteractionCode}))

	users.awaitDelivery(t)

	users.mu.Lock()
	qt.Check(t, qt.DeepEquals(users.registrationMails, []string{"u3"}))
	users.mu.Unlock()
}

func TestRegistrationConflictOnAnotherVerifiedChannelNotifiesItsOwner(t *testing.T) {
	users := newVerificationUsers()

	a, err := New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(registeringClient()),
		PasswordResetRegistry(users.resetMethods()),
		ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)),
		ContactVerification(ChannelPhone, reset.Code(users.deliver("sms"), 6)))
	qt.Assert(t, qt.IsNil(err))

	users.setContacts("fresh", ChannelPhone, Contact{Address: "+37120000000", Verified: true})

	// The email is new, the phone belongs to fresh, who is told about it.
	taken, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "newbie",
		Contacts: map[string]string{ChannelEmail: "newbie@example.com", ChannelPhone: "+37120000000"}, Password: "pw123456"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(uniform(t, taken), RegisterResult{Accepted: true, Interaction: reset.InteractionCode}))

	users.awaitDelivery(t)

	users.mu.Lock()
	qt.Check(t, qt.DeepEquals(users.registrationMails, []string{"u3"}))
	users.mu.Unlock()
}

func TestRegistrationConflictOnUnverifiedChannelAnswersOpenly(t *testing.T) {
	a, _ := newVerificationTestAuth(t, registeringClient(), false)

	// Phone has no verification, so its conflict is answered as without any.
	_, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "newbie",
		Contacts: map[string]string{ChannelEmail: "newbie@example.com", ChannelPhone: "+37120000000"}, Password: "pw123456"})
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrUserAlreadyExists)))

	oe, ok := errors.AsType[*OAuthError](err)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(oe.StatusCode(), http.StatusConflict))
}

func TestContactVerificationRequiresContactVerifier(t *testing.T) {
	_, err := New(newApp(t), validConfig(), fakeUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry(),
		ContactVerification(ChannelEmail, reset.Code(newVerificationUsers().deliver("email"), 6)))
	qt.Check(t, qt.ErrorMatches(err, "contact verification requires .*"))
}

func TestEmailVerificationComesBeforeMFASetup(t *testing.T) {
	users := newVerificationUsers()
	store := mfa.NewMemoryStore()

	a, err := New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyRequired)),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)), MFAStore(store))
	qt.Assert(t, qt.IsNil(err))

	// Nothing may be bound to an account before its address is proven.
	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Status, session.StatusPendingStep))
	qt.Check(t, qt.Equals(pending.Step, stepVerifyEmail))

	_, err = a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: pending.StepToken, Method: "totp"})
	qt.Check(t, qt.IsNotNil(err))

	next := resolveStep(t, a, pending, stepVerifyEmail, `{"code":"`+users.awaitDelivery(t)+`"}`)
	qt.Check(t, qt.Equals(next.Status, session.StatusPendingMFASetup))
}

func TestPhoneVerificationRunsAfterEmailBeforePasswordChange(t *testing.T) {
	users := newVerificationUsers()

	a, err := New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()),
		ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)),
		ContactVerification(ChannelPhone, reset.Code(users.deliver("sms"), 6)))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(a.ContactChannels(), []string{ChannelEmail, ChannelPhone}))

	// Alice has no phone number, so only her email is verified.
	qt.Check(t, qt.Equals(loginAs(t, a, alice("")).Step, stepVerifyEmail))
	users.awaitDelivery(t)

	pending := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "fresh", Password: "changeme"})
	qt.Assert(t, qt.Equals(pending.Step, stepVerifyEmail))

	phone := resolveStep(t, a, pending, stepVerifyEmail, `{"code":"`+users.awaitDelivery(t)+`"}`)
	qt.Assert(t, qt.Equals(phone.Step, "verify_phone"))

	next := resolveStep(t, a, phone, "verify_phone", `{"code":"`+users.awaitDelivery(t)+`"}`)
	qt.Check(t, qt.Equals(next.Status, session.StatusPendingPasswordChange))

	qt.Check(t, qt.IsTrue(users.user("fresh").Contacts[ChannelPhone][0].Verified))
}

func TestLoginEvaluationLoadsTheUserOnce(t *testing.T) {
	users := newVerificationUsers()

	a, err := New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()),
		ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)),
		ContactVerification(ChannelPhone, reset.Code(users.deliver("sms"), 6)))
	qt.Assert(t, qt.IsNil(err))

	gets := func() int {
		users.mu.Lock()
		defer users.mu.Unlock()

		n := users.gets
		users.gets = 0

		return n
	}

	// Both channels' gates and the verification prompt share one load.
	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Step, stepVerifyEmail))
	users.awaitDelivery(t)
	qt.Check(t, qt.Equals(gets(), 1))

	// A wrong code and the prompt that follows it share one load too.
	retry := resolveStep(t, a, pending, stepVerifyEmail, `{"code":"000000x"}`)
	qt.Check(t, qt.Equals(retry.Data["error"], any("invalid_response")))
	qt.Check(t, qt.Equals(gets(), 1))

	users.setContacts("alice", ChannelEmail, Contact{Address: "alice@example.com", Verified: true})
	gets()

	// The gates and the password change check share one load.
	qt.Check(t, qt.Equals(loginAs(t, a, alice("")).Status, session.StatusActive))
	qt.Check(t, qt.Equals(gets(), 1))
}

func TestNewRejectsDuplicateContactChannel(t *testing.T) {
	users := newVerificationUsers()

	_, err := New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(), PasswordResetRegistry(users.resetMethods()),
		ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)),
		ContactVerification(ChannelEmail, reset.Link(users.deliver("email"))))
	qt.Check(t, qt.ErrorMatches(err, `duplicate login step "verify_email"`))
}

func TestRegistrationNoticeMatchesContactNotUsername(t *testing.T) {
	a, users := newVerificationTestAuth(t, registeringClient(), false)

	// "alice" is a username, not anyone's email, so nobody is told about it.
	reg, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "mallory", Contacts: map[string]string{ChannelEmail: "alice"}, Password: "pw123456"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(reg.Accepted))

	users.mu.Lock()
	qt.Check(t, qt.HasLen(users.registrationMails, 0))
	users.mu.Unlock()
}

func TestRegistrationLimitsContacts(t *testing.T) {
	a, users := newAccountTestAuth(t, registeringClient())

	register := func(contacts map[string]string) error {
		_, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Contacts: contacts, Password: "pw123456"})

		return err
	}

	many := make(map[string]string, 9)
	for i := range 9 {
		many[fmt.Sprintf("c%d", i)] = "x"
	}

	for name, contacts := range map[string]map[string]string{
		"too many":     many,
		"bad channel":  {"Email!": "bob@example.com"},
		"long channel": {strings.Repeat("c", 33): "x"},
		"long address": {"address": strings.Repeat("a", 4097)},
	} {
		err := register(contacts)
		qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest), qt.Commentf(name))
	}

	// A multi-line postal address is fine.
	qt.Assert(t, qt.IsNil(register(map[string]string{"address": "Brivibas iela 1\nRiga, LV-1010"})))

	users.mu.Lock()
	qt.Check(t, qt.Equals(users.users["bob"].Name, "bob"))
	users.mu.Unlock()
}

// activeAlice signs alice in through the verification test setup and returns her access token.
func activeAlice(t *testing.T, a *Auth) string {
	t.Helper()

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Step, "agreement"))

	return resolveStep(t, a, pending, "agreement", `{"accept":"v1"}`).AccessToken
}

func TestOneVerifiedContactIsEnough(t *testing.T) {
	a, users := newVerificationTestAuth(t, mfaClient(client.MFAPolicyDisabled), false)
	users.setContacts("alice", ChannelEmail, Contact{Address: "a1@example.com", Verified: true}, Contact{Address: "a2@example.com"})

	// The unverified second address does not hold the login.
	qt.Check(t, qt.Equals(loginAs(t, a, alice("")).Step, "agreement"))
}

func TestUnverifiedPrimaryIsTheAddressToVerify(t *testing.T) {
	a, users := newVerificationTestAuth(t, mfaClient(client.MFAPolicyDisabled), false)
	users.setContacts("alice", ChannelEmail, Contact{Address: "a1@example.com"}, Contact{Address: "a2@example.com", Primary: true})

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Step, stepVerifyEmail))

	// Only the address being verified is handed to the deliverer.
	secret := users.awaitDelivery(t)
	qt.Check(t, qt.DeepEquals(users.lastSeen(), map[string][]Contact{ChannelEmail: {{Address: "a2@example.com"}}}))

	next := resolveStep(t, a, pending, stepVerifyEmail, `{"code":"`+secret+`"}`)
	qt.Check(t, qt.Equals(next.Step, "agreement"))

	// Verifying one address satisfies the channel; the other stays unverified.
	contacts := users.user("alice").Contacts[ChannelEmail]
	qt.Check(t, qt.DeepEquals(contacts, []Contact{{Address: "a1@example.com"}, {Address: "a2@example.com", Verified: true, Primary: true}}))
}

func TestResetUsesOnlyVerifiedContacts(t *testing.T) {
	a, users := newVerificationTestAuth(t, mfaClient(client.MFAPolicyDisabled), false)

	// Reaching only an unverified address is a decoy: nothing is delivered.
	users.setContacts("alice", ChannelEmail, Contact{Address: "a1@example.com", Primary: true})
	requestReset(t, a, "alice", "email")

	users.mu.Lock()
	qt.Check(t, qt.HasLen(users.seen, 0))
	users.mu.Unlock()

	// A verified address is used, the primary first, and the unverified one is never exposed.
	users.setContacts("alice", ChannelEmail,
		Contact{Address: "a1@example.com", Primary: true},
		Contact{Address: "a2@example.com", Verified: true},
		Contact{Address: "a3@example.com", Verified: true, Primary: true},
	)
	requestReset(t, a, "alice", "email")
	users.awaitDelivery(t)

	qt.Check(t, qt.DeepEquals(users.lastSeen(), map[string][]Contact{ChannelEmail: {
		{Address: "a3@example.com", Verified: true, Primary: true},
		{Address: "a2@example.com", Verified: true},
	}}))
}

func TestAddContactVerifiesBeforeJoiningTheAccount(t *testing.T) {
	a, users := newVerificationTestAuth(t, mfaClient(client.MFAPolicyDisabled), false)
	users.setContacts("alice", ChannelEmail, Contact{Address: "alice@example.com", Verified: true, Primary: true})

	tok := activeAlice(t, a)

	_, err := a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: "fax", Address: "x"})
	qt.Check(t, qt.Equals(err.(*OAuthError).StatusCode(), 404))

	_, err = a.AddContact(context.Background(), ContactRequest{Token: "", Channel: ChannelEmail, Address: "second@example.com"})
	qt.Check(t, qt.IsNotNil(err))

	added, err := a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "second@example.com"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(added.Interaction, reset.InteractionCode))

	secret := users.awaitDelivery(t)
	qt.Check(t, qt.DeepEquals(users.lastSeen(), map[string][]Contact{ChannelEmail: {{Address: "second@example.com"}}}))

	// Nothing joins the account before the proof.
	qt.Check(t, qt.HasLen(users.user("alice").Contacts[ChannelEmail], 1))

	err = a.VerifyContact(context.Background(), ContactVerificationRequest{Request: added.Request, Response: map[string]any{"code": "000000x"}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	qt.Assert(t, qt.IsNil(a.VerifyContact(context.Background(), ContactVerificationRequest{Request: added.Request, Response: map[string]any{"code": secret}})))
	qt.Check(t, qt.DeepEquals(users.user("alice").Contacts[ChannelEmail], []Contact{
		{Address: "alice@example.com", Verified: true, Primary: true},
		{Address: "second@example.com", Verified: true},
	}))

	listed, err := a.ListContacts(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(listed[ChannelEmail], 2))
}

// failingStore is a contact store whose lookups of open requests fail.
type failingStore struct {
	contact.Store
}

func (failingStore) Open(context.Context, string, string, string) (*reset.Request, error) {
	return nil, errors.New("store unavailable")
}

func TestFailedRemoveContactChangesNothing(t *testing.T) {
	a, users := newVerificationTestAuth(t, mfaClient(client.MFAPolicyDisabled), false)
	users.setContacts("alice", ChannelEmail,
		Contact{Address: "a1@example.com", Verified: true, Primary: true},
		Contact{Address: "a2@example.com", Verified: true},
	)

	tok := activeAlice(t, a)
	a.verifications = failingStore{a.verifications}

	// The pending proof cannot be cleared, so the address stays rather than leave a proof behind.
	err := a.RemoveContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "a2@example.com"})
	qt.Check(t, qt.IsNotNil(err))
	qt.Check(t, qt.HasLen(users.user("alice").Contacts[ChannelEmail], 2))
}

func TestPrimaryAndRemoveContact(t *testing.T) {
	a, users := newVerificationTestAuth(t, mfaClient(client.MFAPolicyDisabled), false)
	users.setContacts("alice", ChannelEmail,
		Contact{Address: "a1@example.com", Verified: true, Primary: true},
		Contact{Address: "a2@example.com", Verified: true},
		Contact{Address: "a3@example.com"},
	)

	tok := activeAlice(t, a)
	change := func(address string) ContactRequest {
		return ContactRequest{Token: tok, Channel: ChannelEmail, Address: address}
	}

	// An unverified address cannot become primary.
	qt.Check(t, qt.Equals(oauthErrorCode(t, a.SetPrimaryContact(context.Background(), change("a3@example.com"))), ErrCodeInvalidRequest))

	qt.Assert(t, qt.IsNil(a.SetPrimaryContact(context.Background(), change("a2@example.com"))))

	primary, _ := users.user("alice").PreferredContact(ChannelEmail)
	qt.Check(t, qt.Equals(primary.Address, "a2@example.com"))

	// Removing an address cancels its pending verification, so an earlier proof cannot bring it back.
	added, err := a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "late@example.com"})
	qt.Assert(t, qt.IsNil(err))

	secret := users.awaitDelivery(t)

	qt.Assert(t, qt.IsNil(a.RemoveContact(context.Background(), change("late@example.com"))))

	err = a.VerifyContact(context.Background(), ContactVerificationRequest{Request: added.Request, Response: map[string]any{"code": secret}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	qt.Assert(t, qt.IsNil(a.RemoveContact(context.Background(), change("a1@example.com"))))
	qt.Check(t, qt.HasLen(users.user("alice").Contacts[ChannelEmail], 2))
}

func TestCancelContactVerification(t *testing.T) {
	a, users := newVerificationTestAuth(t, mfaClient(client.MFAPolicyDisabled), false)
	users.setContacts("alice", ChannelEmail, Contact{Address: "alice@example.com", Verified: true, Primary: true})

	tok := activeAlice(t, a)

	added, err := a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "late@example.com"})
	qt.Assert(t, qt.IsNil(err))

	secret := users.awaitDelivery(t)

	// An admin tool removed the address directly, then cancels its pending proof.
	qt.Assert(t, qt.IsNil(a.CancelContactVerification(context.Background(), "u1", ChannelEmail, "late@example.com")))

	err = a.VerifyContact(context.Background(), ContactVerificationRequest{Request: added.Request, Response: map[string]any{"code": secret}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
	qt.Check(t, qt.HasLen(users.user("alice").Contacts[ChannelEmail], 1))

	// Nothing pending is not an error.
	qt.Check(t, qt.IsNil(a.CancelContactVerification(context.Background(), "u1", ChannelEmail, "late@example.com")))
}

func TestRegistrationsCannotSpendTheOwnersDeliveries(t *testing.T) {
	users := newAccountUsers()
	users.claimable[ChannelEmail] = true

	cfg := validConfig()
	cfg.Throttle.ContactDeliveryMax = 1

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(registeringClient()),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)))
	qt.Assert(t, qt.IsNil(err))

	// Registrations naming the address spend only their own accounts' budgets.
	for _, name := range []string{"bob", "carol"} {
		reg, err := a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: name, Contacts: map[string]string{ChannelEmail: "victim@example.com"}, Password: "pw123456"})
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.IsTrue(reg.Accepted))

		users.awaitDelivery(t)
	}

	tok := loginAs(t, a, alice("")).AccessToken

	_, err = a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "victim@example.com"})
	qt.Check(t, qt.IsNil(err))

	users.awaitDelivery(t)

	users.mu.Lock()
	defer users.mu.Unlock()

	victim := 0

	for _, seen := range users.seen {
		if seen[ChannelEmail][0].Address == "victim@example.com" {
			victim++
		}
	}

	qt.Check(t, qt.Equals(victim, 3))
}

func TestContactGuessesAreCappedPerAddress(t *testing.T) {
	users := newVerificationUsers()
	users.setContacts("alice", ChannelEmail, Contact{Address: "alice@example.com", Verified: true, Primary: true})

	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute, MFAResendCooldown: -1}

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)), LoginSteps(newAgreementStep("v1")))
	qt.Assert(t, qt.IsNil(err))

	tok := activeAlice(t, a)

	add := func() (string, string) {
		added, err := a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "second@example.com"})
		qt.Assert(t, qt.IsNil(err))

		return added.Request, users.awaitDelivery(t)
	}

	first, _ := add()

	for i := range 2 {
		err := a.VerifyContact(context.Background(), ContactVerificationRequest{Request: first, Response: map[string]any{"code": "000000x"}, IP: fmt.Sprintf("192.0.2.%d", i)})
		qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
	}

	// A resend and a fresh IP do not bring new guesses, not even for the right code.
	second, code := add()

	err = a.VerifyContact(context.Background(), ContactVerificationRequest{Request: second, Response: map[string]any{"code": code}, IP: "192.0.2.9"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))
	qt.Check(t, qt.HasLen(users.user("alice").Contacts[ChannelEmail], 1))
}

func TestContactGuessesAreSharedWithTheLoginStep(t *testing.T) {
	users := newVerificationUsers()

	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)))
	qt.Assert(t, qt.IsNil(err))

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Step, stepVerifyEmail))

	code := users.awaitDelivery(t)
	request := users.lastRequest("u1")

	for i := range 2 {
		err := a.VerifyContact(context.Background(), ContactVerificationRequest{Request: request, Response: map[string]any{"code": "000000x"}, IP: fmt.Sprintf("192.0.2.%d", i)})
		qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
	}

	// The guesses spent outside the login also hold the login step.
	_, err = a.ResolveStep(context.Background(), StepRequest{Token: pending.StepToken, Name: stepVerifyEmail, Payload: []byte(`{"code":"` + code + `"}`)})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))
}

func TestConcurrentContactSendsStayUnderTheResendCap(t *testing.T) {
	a, users := newVerificationTestAuth(t, mfaClient(client.MFAPolicyDisabled), false)
	users.setContacts("alice", ChannelEmail, Contact{Address: "alice@example.com", Verified: true, Primary: true})

	tok := activeAlice(t, a)

	a.Config().Throttle.MFAMaxResends = 1
	a.Config().Throttle.MFAResendCooldown = -1

	// Each send is counted before it goes out, so racing sends cannot all pass the cap.
	var wg sync.WaitGroup

	for range 8 {
		wg.Go(func() {
			_, _ = a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "a1@example.com"})
		})
	}

	wg.Wait()

	users.mu.Lock()
	defer users.mu.Unlock()

	qt.Check(t, qt.HasLen(users.delivered["u1"], 2))
}

func TestContactLimitsKeyTheNormalizedAddress(t *testing.T) {
	a, _ := newVerificationTestAuth(t, mfaClient(client.MFAPolicyDisabled), false)

	c := a.contactStep(ChannelEmail)

	// The provider's spelling and the canonical one share the guess, resend and delivery limits.
	qt.Check(t, qt.Equals(c.addressKey("u1", " Alice@Example.COM "), c.addressKey("u1", "alice@example.com")))
	qt.Check(t, qt.Not(qt.Equals(c.addressKey("u1", "alice@example.com"), c.addressKey("u2", "alice@example.com"))))
}

func TestContactResendCapIsPerAddress(t *testing.T) {
	a, users := newVerificationTestAuth(t, mfaClient(client.MFAPolicyDisabled), false)
	users.setContacts("alice", ChannelEmail, Contact{Address: "alice@example.com", Verified: true, Primary: true})

	tok := activeAlice(t, a)

	a.Config().Throttle.MFAMaxResends = 1
	a.Config().Throttle.MFAResendCooldown = -1
	a.Config().ContactVerificationTTL = 3 * time.Hour

	for range 2 {
		_, err := a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "a1@example.com"})
		qt.Assert(t, qt.IsNil(err))
		users.awaitDelivery(t)
	}

	// The refusal reports when the address's own counter resets.
	_, err := a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "a1@example.com"})
	oe, ok := errors.AsType[*OAuthError](err)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(oe.Code, ErrCodeSlowDown))
	qt.Check(t, qt.IsTrue(oe.RetryAfter > 3*time.Hour-time.Minute && oe.RetryAfter <= 3*time.Hour))

	// Another address has a cap of its own.
	_, err = a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "a2@example.com"})
	qt.Assert(t, qt.IsNil(err))
	users.awaitDelivery(t)
}

func TestContactSendsAreCappedPerUser(t *testing.T) {
	users := newVerificationUsers()
	users.setContacts("alice", ChannelEmail, Contact{Address: "alice@example.com", Verified: true, Primary: true})

	cfg := validConfig()
	cfg.Throttle.ContactSendMax = 2
	cfg.ContactVerificationTTL = 3 * time.Hour

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)), LoginSteps(newAgreementStep("v1")))
	qt.Assert(t, qt.IsNil(err))

	tok := activeAlice(t, a)

	for _, address := range []string{"a1@example.com", "a2@example.com"} {
		_, err := a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: address})
		qt.Assert(t, qt.IsNil(err))
		users.awaitDelivery(t)
	}

	// A fresh address does not escape the user's cap.
	_, err = a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "a3@example.com"})
	oe, ok := errors.AsType[*OAuthError](err)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(oe.Code, ErrCodeSlowDown))
	qt.Check(t, qt.IsTrue(oe.RetryAfter > 3*time.Hour-time.Minute && oe.RetryAfter <= 3*time.Hour))
}

func TestUndeliveredVerificationKeepsTheAddressCap(t *testing.T) {
	users := newVerificationUsers()
	users.setContacts("alice", ChannelEmail, Contact{Address: "alice@example.com", Verified: true, Primary: true})

	cfg := validConfig()
	cfg.Throttle.ContactDeliveryMax = 1

	// An sms deliverer cannot reach an email address, so nothing is ever sent.
	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("sms"), 6)), LoginSteps(newAgreementStep("v1")))
	qt.Assert(t, qt.IsNil(err))

	tok := activeAlice(t, a)

	for range 2 {
		_, err := a.AddContact(context.Background(), ContactRequest{Token: tok, Channel: ChannelEmail, Address: "second@example.com"})
		qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
	}
}

func TestThrottledDeliveryStillParksLogin(t *testing.T) {
	users := newVerificationUsers()

	cfg := validConfig()
	cfg.Throttle.ContactDeliveryMax = 1

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)))
	qt.Assert(t, qt.IsNil(err))

	first := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(first.Step, stepVerifyEmail))
	users.awaitDelivery(t)

	// With the code withdrawn and the address's budget spent, the login still waits at the step.
	qt.Assert(t, qt.IsNil(a.CancelContactVerification(context.Background(), "u1", ChannelEmail, "alice@example.com")))

	second := loginAs(t, a, alice(""))
	qt.Check(t, qt.Equals(second.Step, stepVerifyEmail))
	qt.Check(t, qt.IsTrue(second.StepToken != ""))
	qt.Check(t, qt.Equals(second.Data["error"], any("delivery_throttled")))
}

func TestResendIsNoFailedAttempt(t *testing.T) {
	users := newVerificationUsers()

	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)))
	qt.Assert(t, qt.IsNil(err))

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Step, stepVerifyEmail))
	users.awaitDelivery(t)

	// A resend is no guess, so with two attempts allowed a typo still leaves room for the code.
	resolveStep(t, a, pending, stepVerifyEmail, `{"resend":true}`)
	code := users.awaitDelivery(t)

	resolveStep(t, a, pending, stepVerifyEmail, `{"code":"000000x"}`)

	res := resolveStep(t, a, pending, stepVerifyEmail, `{"code":"`+code+`"}`)
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))
}

func TestPendingVerificationPollIsNoFailedAttempt(t *testing.T) {
	users := newVerificationUsers()
	m := &approvalMethod{approved: map[string]bool{}}

	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, m))
	qt.Assert(t, qt.IsNil(err))

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Step, stepVerifyEmail))

	// Polling while approval is outstanding is no guess.
	for range 3 {
		res := resolveStep(t, a, pending, stepVerifyEmail, `{}`)
		qt.Check(t, qt.Equals(res.Status, session.StatusPendingStep))
		qt.Check(t, qt.Equals(res.Data["pending"], any(true)))
	}

	req, err := a.verifications.Open(context.Background(), ChannelEmail, "u1", "alice@example.com")
	qt.Assert(t, qt.IsNil(err))

	m.mu.Lock()
	m.approved[req.ID] = true
	m.mu.Unlock()

	res := resolveStep(t, a, pending, stepVerifyEmail, `{}`)
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))
}

func TestDefaultAddressNormalizer(t *testing.T) {
	for _, tc := range []struct{ channel, in, want string }{
		{ChannelEmail, "  Alice@Example.COM ", "alice@example.com"},
		{ChannelPhone, " +371 (2) 000-00.00 ", "+37120000000"},
		{"address", "  Brivibas iela 1\nRiga  ", "Brivibas iela 1\nRiga"},
	} {
		qt.Check(t, qt.Equals(DefaultAddressNormalizer.Normalize(tc.channel, tc.in), tc.want), qt.Commentf(tc.channel))
	}
}

func TestAddressesAreNormalized(t *testing.T) {
	users := newAccountUsers()

	a, err := New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(registeringClient()),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelEmail, reset.Code(users.deliver("email"), 6)))
	qt.Assert(t, qt.IsNil(err))

	// The user provider stores the canonical form.
	_, err = a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Contacts: map[string]string{ChannelEmail: " Victim@Example.COM "}, Password: "pw123456"})
	qt.Assert(t, qt.IsNil(err))
	users.awaitDelivery(t)

	qt.Check(t, qt.Equals(users.user("bob").Contacts[ChannelEmail][0].Address, "victim@example.com"))
}

func TestCustomAddressNormalization(t *testing.T) {
	users := newAccountUsers()

	// A national number gets its country code.
	normalize := AddressNormalizerFunc(func(channel, address string) string {
		address = DefaultAddressNormalizer.Normalize(channel, address)
		if channel == ChannelPhone && !strings.HasPrefix(address, "+") {
			return "+371" + address
		}

		return address
	})

	a, err := New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(registeringClient()),
		PasswordResetRegistry(users.resetMethods()), ContactVerification(ChannelPhone, reset.Code(users.deliver("sms"), 6)), AddressNormalization(normalize))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(a.NormalizeAddress(ChannelPhone, "2000 0000"), "+37120000000"))

	_, err = a.Register(context.Background(), RegisterRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Contacts: map[string]string{ChannelPhone: "2000 1111"}, Password: "pw123456"})
	qt.Assert(t, qt.IsNil(err))

	users.mu.Lock()
	defer users.mu.Unlock()

	qt.Check(t, qt.Equals(users.users["bob"].Contacts[ChannelPhone][0].Address, "+37120001111"))
}

func TestResetWithoutContactVerificationUsesAppAddresses(t *testing.T) {
	// Nothing verifies addresses here, so the app's own address is the one to use.
	users := newVerificationUsers()

	a, err := New(newApp(t), validConfig(), users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		PasswordResetRegistry(users.resetMethods()))
	qt.Assert(t, qt.IsNil(err))

	requestReset(t, a, "alice", "email")
	users.awaitDelivery(t)

	qt.Check(t, qt.DeepEquals(users.lastSeen(), map[string][]Contact{ChannelEmail: {{Address: "alice@example.com", Primary: true}}}))
}
