package auth

import (
	"context"
	"net/url"
	"sync"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/internal/mfatest"
	"azugo.io/auth/mfa"
	_ "azugo.io/auth/mfa/recovery"
	"azugo.io/auth/mfa/totp"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"github.com/go-quicktest/qt"
)

// mfaClient is a JSON portal client with the given MFA policy.
func mfaClient(policy client.MFAPolicy) *client.Client {
	return &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
		MFAPolicy: policy,
	}
}

func newMFATestAuth(t *testing.T, cl *client.Client, store mfa.Store, opts ...Option) *Auth {
	t.Helper()

	return newServiceTestAuth(t, cl, append([]Option{MFAStore(store)}, opts...)...)
}

func loginAs(t *testing.T, a *Auth, in LoginRequest) LoginResult {
	t.Helper()

	res, err := a.Login(context.Background(), in)
	qt.Assert(t, qt.IsNil(err))

	return res
}

func alice(acrValues string) LoginRequest {
	return LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", ACRValues: acrValues}
}

// nextCode returns the code for the time step after the current one, which the replay guard
// still accepts (skew 1) even though the enrollment consumed the current step.
func nextCode(t *testing.T, seed string) string {
	t.Helper()

	code, err := totp.GenerateCode(seed, time.Now().Add(30*time.Second))
	qt.Assert(t, qt.IsNil(err))

	return code
}

// enrollTOTP runs the enrollment ceremony over tok and returns the seed.
func enrollTOTP(t *testing.T, a *Auth, tok string) string {
	t.Helper()

	data, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: tok, Method: totp.DriverName})
	qt.Assert(t, qt.IsNil(err))

	seed, _ := data["secret"].(string)
	qt.Assert(t, qt.IsTrue(seed != ""))
	qt.Check(t, qt.IsTrue(data["uri"] != ""))

	code, err := totp.GenerateCode(seed, time.Now())
	qt.Assert(t, qt.IsNil(err))

	_, err = a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: tok, Method: totp.DriverName, Response: map[string]any{"code": code}})
	qt.Assert(t, qt.IsNil(err))

	return seed
}

func TestLoginWithoutMFAStoreIgnoresPolicy(t *testing.T) {
	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyRequired))

	res := loginAs(t, a, alice(""))
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))
	qt.Check(t, qt.IsTrue(res.AccessToken != ""))
	qt.Check(t, qt.DeepEquals(res.AMR, []string{"pwd"}))
}

func TestLoginDisabledPolicyIgnoresEnrollment(t *testing.T) {
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyDisabled), mfa.NewMemoryStore())

	first := loginAs(t, a, alice(""))
	enrollTOTP(t, a, first.AccessToken)

	res := loginAs(t, a, alice(""))
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))
}

func TestLoginOptionalMFAPromptsEnrolledUser(t *testing.T) {
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyOptional), mfa.NewMemoryStore())

	first := loginAs(t, a, alice(""))
	qt.Check(t, qt.Equals(first.Status, session.StatusActive))

	seed := enrollTOTP(t, a, first.AccessToken)

	res := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(res.Status, session.StatusPendingMFA))
	qt.Check(t, qt.Equals(res.AccessToken, ""))
	qt.Check(t, qt.IsTrue(res.StepToken != ""))
	qt.Check(t, qt.DeepEquals(res.Available, []string{totp.DriverName}))
	qt.Check(t, qt.Equals(res.Selected, totp.DriverName))
	qt.Check(t, qt.Equals(res.Interaction, mfa.InteractionCode))
	qt.Assert(t, qt.IsNotNil(res.Cookie))

	// Neither the step token nor the pending cookie authenticate a request.
	_, _, err := a.IntrospectToken(context.Background(), res.StepToken)
	qt.Check(t, qt.IsNotNil(err))
	_, _, err = a.IntrospectToken(context.Background(), res.Cookie.Value)
	qt.Check(t, qt.IsNotNil(err))

	// A wrong code is a failed attempt.
	_, err = a.VerifyMFA(context.Background(), MFAStepRequest{Token: res.StepToken, Response: map[string]any{"code": "000000"}})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	code := nextCode(t, seed)

	done, err := a.VerifyMFA(context.Background(), MFAStepRequest{Token: res.StepToken, Response: map[string]any{"code": code}})
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(done.Status, session.StatusActive))
	qt.Check(t, qt.IsTrue(done.AccessToken != ""))
	qt.Check(t, qt.DeepEquals(done.AMR, []string{"pwd", "otp", "mfa"}))

	info, sess, err := a.IntrospectToken(context.Background(), done.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.MFAMethod, totp.DriverName))
	qt.Check(t, qt.DeepEquals(info.AMR, []string{"pwd", "otp", "mfa"}))
	qt.Check(t, qt.IsTrue(sess.ExpiresAt.After(time.Now().Add(7*time.Hour))))

	// The step token is retired once the session is active.
	_, err = a.VerifyMFA(context.Background(), MFAStepRequest{Token: res.StepToken, Response: map[string]any{"code": code}})
	qt.Check(t, qt.IsNotNil(err))
}

func TestMFARejectsMissingPendingState(t *testing.T) {
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyOptional), mfa.NewMemoryStore())

	first := loginAs(t, a, alice(""))
	enrollTOTP(t, a, first.AccessToken)

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Status, session.StatusPendingMFA))

	claims, err := a.codec.DecodeSession(pending.StepToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(deleteSynced(context.Background(), a.pending, claims.SessionID)))

	_, err = a.BeginMFA(context.Background(), MFAStepRequest{Token: pending.StepToken})
	qt.Check(t, qt.ErrorIs(err, token.ErrInvalidToken))
}

func TestLoginRequiredMFAOnboardsUnenrolledUser(t *testing.T) {
	store := mfa.NewMemoryStore()
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyRequired), store)

	res := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(res.Status, session.StatusPendingMFASetup))
	qt.Check(t, qt.IsTrue(res.StepToken != ""))

	methods, err := a.ListMFAMethods(context.Background(), res.StepToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(len(methods) >= 2))

	data, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: res.StepToken, Method: totp.DriverName})
	qt.Assert(t, qt.IsNil(err))

	seed, _ := data["secret"].(string)

	// A wrong first code does not enroll.
	_, err = a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: res.StepToken, Method: totp.DriverName, Response: map[string]any{"code": "000000"}})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	code, err := totp.GenerateCode(seed, time.Now())
	qt.Assert(t, qt.IsNil(err))

	out, err := a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: res.StepToken, Method: totp.DriverName, Response: map[string]any{"code": code}})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(out.Login))
	qt.Check(t, qt.Equals(out.Login.Status, session.StatusActive))
	qt.Check(t, qt.IsTrue(out.Login.AccessToken != ""))

	enrolled, err := mfa.Enrolled(context.Background(), store, "u1", totp.DriverName)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(enrolled, 1))
	qt.Check(t, qt.Equals(enrolled[0].ID, out.EnrollmentID))
}

func TestLoginRequiredMFAWithoutPermittedMethodFails(t *testing.T) {
	cl := mfaClient(client.MFAPolicyRequired)
	cl.AllowedMFAMethods = []string{"nope"}
	a := newMFATestAuth(t, cl, mfa.NewMemoryStore())

	_, err := a.Login(context.Background(), alice(""))
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnmetAuthenticationRequirements))
}

func TestMFASwitchResendAndAsyncStatus(t *testing.T) {
	store := mfa.NewMemoryStore()
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyOptional), store)
	a.Config().Throttle.MFAResendCooldown = 0
	a.Config().Throttle.MFAMaxResends = 1

	first := loginAs(t, a, alice(""))
	seed := enrollTOTP(t, a, first.AccessToken)

	// Adding a second factor needs a session that passed the first one.
	verified := verifyTOTP(t, a, loginAs(t, a, alice("")), seed)

	_, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: verified.AccessToken, Method: "push"})
	qt.Assert(t, qt.IsNil(err))

	_, err = a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: verified.AccessToken, Method: "push", Response: map[string]any{"device": "phone-1"}})
	qt.Assert(t, qt.IsNil(err))

	res := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(res.Status, session.StatusPendingMFA))
	qt.Check(t, qt.DeepEquals(res.Available, []string{totp.DriverName, "push"}))
	qt.Check(t, qt.Equals(res.Selected, totp.DriverName))

	// TOTP has nothing to resend.
	_, err = a.ResendMFA(context.Background(), MFAStepRequest{Token: res.StepToken})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	// Verifying with a method that is not selected is refused.
	_, err = a.VerifyMFA(context.Background(), MFAStepRequest{Token: res.StepToken, Method: "push", Response: map[string]any{"code": "1"}})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	sw, err := a.BeginMFA(context.Background(), MFAStepRequest{Token: res.StepToken, Method: "push"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sw.Status, session.StatusPendingMFA))
	qt.Check(t, qt.Equals(sw.Selected, "push"))
	qt.Check(t, qt.Equals(sw.Interaction, mfa.InteractionPoll))
	qt.Check(t, qt.IsTrue(sw.Data["transaction"] != ""))

	// Polling keeps the challenge pending, and the login client cannot approve it itself.
	st, err := a.MFAStatus(context.Background(), MFAStepRequest{Token: res.StepToken})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(st.Status, session.StatusPendingMFA))

	st, err = a.VerifyMFA(context.Background(), MFAStepRequest{Token: res.StepToken, Response: map[string]any{"approved": true}})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(st.Status, session.StatusPendingMFA))

	// One resend is allowed, the second exceeds the cap.
	_, err = a.ResendMFA(context.Background(), MFAStepRequest{Token: res.StepToken})
	qt.Assert(t, qt.IsNil(err))

	_, err = a.ResendMFA(context.Background(), MFAStepRequest{Token: res.StepToken})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))

	// Approval lands out-of-band; the next poll completes the login.
	approvePush(t, a, "u1")

	done, err := a.MFAStatus(context.Background(), MFAStepRequest{Token: res.StepToken})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))
	qt.Check(t, qt.DeepEquals(done.AMR, []string{"pwd", "mfa"}))
}

// verifyTOTP completes a pending_mfa login with the next TOTP code and returns the active result.
func verifyTOTP(t *testing.T, a *Auth, pending LoginResult, seed string) LoginResult {
	t.Helper()

	qt.Assert(t, qt.Equals(pending.Status, session.StatusPendingMFA))

	done, err := a.VerifyMFA(context.Background(), MFAStepRequest{Token: pending.StepToken, Response: map[string]any{"code": nextCode(t, seed)}})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(done.Status, session.StatusActive))

	return done
}

// approvePush stands in for the user's device approving the newest push challenge.
func approvePush(t *testing.T, a *Auth, userID string) {
	t.Helper()

	m, err := a.MFAMethods().Get(context.Background(), mfatest.DriverName)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(mfatest.Approve(m, userID, true)))
}

func TestMFAEnrollBeginIsBoundedPerUser(t *testing.T) {
	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a := newGrantsTestAuth(t, cfg, []Option{MFAStore(mfa.NewMemoryStore())}, mfaClient(client.MFAPolicyOptional))
	active := loginAs(t, a, alice(""))

	for range cfg.Throttle.MaxAttempts {
		_, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: active.AccessToken, Method: totp.DriverName})
		qt.Assert(t, qt.IsNil(err))
	}

	_, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: active.AccessToken, Method: totp.DriverName})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))
}

func TestBackupMethodRequiresPrimaryFactor(t *testing.T) {
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyOptional), mfa.NewMemoryStore())
	first := loginAs(t, a, alice(""))

	// Recovery codes prove nothing, so they cannot be the first factor.
	_, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: first.AccessToken, Method: "recovery"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	enrollTOTP(t, a, first.AccessToken)

	_, err = a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: first.AccessToken, Method: "recovery"})
	qt.Assert(t, qt.IsNil(err))

	// A required-MFA client permitting only a backup method cannot onboard anyone.
	cl := mfaClient(client.MFAPolicyRequired)
	cl.AllowedMFAMethods = []string{"recovery"}

	_, err = newMFATestAuth(t, cl, mfa.NewMemoryStore()).Login(context.Background(), alice(""))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnmetAuthenticationRequirements))
}

func TestStepEndpointsEchoOnlyStepTokens(t *testing.T) {
	store := mfa.NewMemoryStore()
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyOptional), store)
	seed := enrollTOTP(t, a, loginAs(t, a, alice("")).AccessToken)

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Status, session.StatusPendingMFA))
	qt.Assert(t, qt.IsNotNil(pending.Cookie))

	// The pending cookie is a valid step credential but is never echoed back to a script.
	res, err := a.MFAStatus(context.Background(), MFAStepRequest{Token: pending.Cookie.Value})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.StepToken, ""))

	res, err = a.MFAStatus(context.Background(), MFAStepRequest{Token: pending.StepToken})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.StepToken, pending.StepToken))

	// Passing the factor with the step token retires the pending cookie as well.
	verifyTOTP(t, a, pending, seed)

	_, err = a.MFAStatus(context.Background(), MFAStepRequest{Token: pending.Cookie.Value})
	qt.Check(t, qt.ErrorIs(err, token.ErrInvalidToken))
	_, err = a.MFAStatus(context.Background(), MFAStepRequest{Token: pending.StepToken})
	qt.Check(t, qt.ErrorIs(err, token.ErrInvalidToken))
}

func TestMFAStatusRepeatsChallengeData(t *testing.T) {
	store := mfa.NewMemoryStore()
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyOptional), store)

	qt.Assert(t, qt.IsNil(store.Enroll(context.Background(), &mfa.Enrollment{ID: "phone", UserID: "u1", Method: "push", Secret: []byte("phone")})))

	res := loginAs(t, a, alice(""))
	qt.Assert(t, qt.IsTrue(res.Data["transaction"] != ""))

	status, err := a.MFAStatus(context.Background(), MFAStepRequest{Token: res.StepToken})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(status.Data, res.Data))
}

func TestMFAResendCooldown(t *testing.T) {
	store := mfa.NewMemoryStore()
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyOptional), store)

	qt.Assert(t, qt.IsNil(store.Enroll(context.Background(), &mfa.Enrollment{ID: "phone", UserID: "u1", Method: "push", Secret: []byte("phone")})))

	res := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(res.Status, session.StatusPendingMFA))
	qt.Check(t, qt.Equals(res.Selected, "push"))

	_, err := a.ResendMFA(context.Background(), MFAStepRequest{Token: res.StepToken})
	qt.Assert(t, qt.IsNotNil(err))

	var oe *OAuthError
	qt.Assert(t, qt.ErrorAs(err, &oe))
	qt.Check(t, qt.Equals(oe.Code, ErrCodeSlowDown))
	// Retry-After is what remains of the cooldown, never more than the configured one.
	qt.Check(t, qt.IsTrue(oe.RetryAfter > 0 && oe.RetryAfter <= a.Config().Throttle.MFAResendCooldown),
		qt.Commentf("got %s", oe.RetryAfter))
}

func TestMFAVerifyLockout(t *testing.T) {
	cfg := validConfig()
	cfg.LogoutInvalidatesCookie = true
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a := newGrantsTestAuth(t, cfg, []Option{MFAStore(mfa.NewMemoryStore())}, mfaClient(client.MFAPolicyOptional))

	first := loginAs(t, a, alice(""))
	enrollTOTP(t, a, first.AccessToken)

	res := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(res.Status, session.StatusPendingMFA))

	for range 2 {
		_, err := a.VerifyMFA(context.Background(), MFAStepRequest{Token: res.StepToken, IP: "10.0.0.9", Response: map[string]any{"code": "000000"}})
		qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
	}

	_, err := a.VerifyMFA(context.Background(), MFAStepRequest{Token: res.StepToken, IP: "10.0.0.9", Response: map[string]any{"code": "000000"}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))
}

func TestRevokeMFAAndListMethods(t *testing.T) {
	store := mfa.NewMemoryStore()
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyOptional), store)

	other := loginAs(t, a, alice(""))
	first := loginAs(t, a, alice(""))
	seed := enrollTOTP(t, a, first.AccessToken)

	// Enrolling the first factor proves the session holds it, so it may add another
	_, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: first.AccessToken, Method: "recovery"})
	qt.Assert(t, qt.IsNil(err))

	info, _, err := a.IntrospectToken(context.Background(), first.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(info.AMR, []string{"pwd", "otp", "mfa"}))

	// ...while a password-only session opened before can neither add nor remove factors.
	_, err = a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: other.AccessToken, Method: "recovery"})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnmetAuthenticationRequirements))

	err = a.RevokeMFA(context.Background(), other.AccessToken, totp.DriverName)
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnmetAuthenticationRequirements))

	verified := verifyTOTP(t, a, loginAs(t, a, alice("")), seed)

	// A second authenticator app enrolls alongside the first, with a label.
	data, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: verified.AccessToken, Method: totp.DriverName})
	qt.Assert(t, qt.IsNil(err))

	code, err := totp.GenerateCode(data["secret"].(string), time.Now())
	qt.Assert(t, qt.IsNil(err))

	second, err := a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: verified.AccessToken, Method: totp.DriverName, Label: "Tablet", Response: map[string]any{"code": code}})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(second.EnrollmentID != ""))

	// A recovery code set is exclusive: enrolling it twice is a conflict.
	_, err = a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: verified.AccessToken, Method: "recovery"})
	qt.Assert(t, qt.IsNil(err))
	_, err = a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: verified.AccessToken, Method: "recovery"})
	qt.Assert(t, qt.IsNil(err))
	_, err = a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: verified.AccessToken, Method: "recovery"})
	qt.Assert(t, qt.IsNotNil(err))

	var conflict *OAuthError
	qt.Assert(t, qt.ErrorAs(err, &conflict))
	qt.Check(t, qt.Equals(conflict.StatusCode(), 409))

	methods, err := a.ListMFAMethods(context.Background(), verified.AccessToken)
	qt.Assert(t, qt.IsNil(err))

	byName := map[string]MFAMethodInfo{}
	for _, m := range methods {
		byName[m.Method] = m
	}

	qt.Assert(t, qt.HasLen(byName[totp.DriverName].Enrollments, 2))
	qt.Check(t, qt.Equals(byName[totp.DriverName].Enrollments[1].Label, "Tablet"))
	// The verified login above touched the first app; the second is unused so far.
	qt.Check(t, qt.IsNotNil(byName[totp.DriverName].Enrollments[0].LastUsedAt))
	qt.Check(t, qt.IsNil(byName[totp.DriverName].Enrollments[1].LastUsedAt))
	qt.Check(t, qt.IsFalse(byName[totp.DriverName].Exclusive))
	qt.Check(t, qt.IsTrue(byName["recovery"].Enrolled))
	qt.Check(t, qt.IsTrue(byName["recovery"].Exclusive))
	qt.Check(t, qt.IsTrue(byName["recovery"].Backup))

	// A login still waiting for its second factor sees what is enrolled, not the devices.
	pendingMethods, err := a.ListMFAMethods(context.Background(), loginAs(t, a, alice("")).StepToken)
	qt.Assert(t, qt.IsNil(err))

	for _, m := range pendingMethods {
		if m.Method == totp.DriverName {
			qt.Check(t, qt.IsTrue(m.Enrolled))
			qt.Check(t, qt.HasLen(m.Enrollments, 0))
		}
	}

	// One enrollment can be removed on its own; the rest of the method stays.
	qt.Assert(t, qt.IsNil(a.RevokeMFAEnrollment(context.Background(), verified.AccessToken, totp.DriverName, second.EnrollmentID)))
	qt.Check(t, qt.Equals(oauthErrorCode(t, a.RevokeMFAEnrollment(context.Background(), verified.AccessToken, totp.DriverName, second.EnrollmentID)), ErrCodeInvalidRequest))
	qt.Check(t, qt.Equals(oauthErrorCode(t, a.RevokeMFAEnrollment(context.Background(), verified.AccessToken, "recovery", byName[totp.DriverName].Enrollments[0].ID)), ErrCodeInvalidRequest))

	list, err := a.EnrolledMFA(context.Background(), "u1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(list, []string{totp.DriverName, "recovery"}))

	qt.Assert(t, qt.IsNil(a.RevokeMFA(context.Background(), verified.AccessToken, totp.DriverName)))
	qt.Assert(t, qt.IsNil(a.RevokeMFA(context.Background(), verified.AccessToken, "recovery")))
	qt.Check(t, qt.Equals(oauthErrorCode(t, a.RevokeMFA(context.Background(), verified.AccessToken, "recovery")), ErrCodeInvalidRequest))

	list, err = a.EnrolledMFA(context.Background(), "u1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(list, 0))

	// Unknown methods 404.
	_, err = a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: verified.AccessToken, Method: "nope"})
	qt.Assert(t, qt.IsNotNil(err))

	var oe *OAuthError
	qt.Assert(t, qt.ErrorAs(err, &oe))
	qt.Check(t, qt.Equals(oe.StatusCode(), 404))
}

// throttledMFAAuth builds an auth with MaxAttempts=2 and a TOTP-enrolled alice.
func throttledMFAAuth(t *testing.T) *Auth {
	t.Helper()

	cfg := validConfig()
	cfg.LogoutInvalidatesCookie = true
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a := newGrantsTestAuth(t, cfg, []Option{MFAStore(mfa.NewMemoryStore())}, mfaClient(client.MFAPolicyOptional))

	first := loginAs(t, a, alice(""))
	enrollTOTP(t, a, first.AccessToken)

	return a
}

func TestMFAThrottleSpansSessions(t *testing.T) {
	a := throttledMFAAuth(t)

	guess := func(tok string) error {
		_, err := a.VerifyMFA(context.Background(), MFAStepRequest{Token: tok, Response: map[string]any{"code": "000000"}})

		return err
	}

	// Failures accumulate per user, so a fresh pending session does not grant fresh guesses.
	one := loginAs(t, a, alice(""))
	qt.Check(t, qt.Equals(oauthErrorCode(t, guess(one.StepToken)), ErrCodeInvalidGrant))

	two := loginAs(t, a, alice(""))
	qt.Check(t, qt.Equals(oauthErrorCode(t, guess(two.StepToken)), ErrCodeInvalidGrant))

	three := loginAs(t, a, alice(""))
	qt.Check(t, qt.Equals(oauthErrorCode(t, guess(three.StepToken)), ErrCodeSlowDown))
}

func TestPasswordSuccessDoesNotResetIPThrottle(t *testing.T) {
	a := throttledMFAAuth(t)

	pending := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", IP: "10.0.0.9"})

	for range 2 {
		_, err := a.VerifyMFA(context.Background(), MFAStepRequest{Token: pending.StepToken, IP: "10.0.0.9", Response: map[string]any{"code": "000000"}})
		qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
	}

	// The IP is locked out; a correct password from it no longer clears the counter.
	_, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", IP: "10.0.0.9"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))
}

func TestMFASuccessDoesNotResetIPThrottle(t *testing.T) {
	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a := newGrantsTestAuth(t, cfg, []Option{MFAStore(mfa.NewMemoryStore())}, mfaClient(client.MFAPolicyOptional))

	first := loginAs(t, a, alice(""))
	seed := enrollTOTP(t, a, first.AccessToken)

	pending := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", IP: "10.0.0.9"})

	_, err := a.VerifyMFA(context.Background(), MFAStepRequest{Token: pending.StepToken, IP: "10.0.0.9", Response: map[string]any{"code": "000000"}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	done, err := a.VerifyMFA(context.Background(), MFAStepRequest{Token: pending.StepToken, IP: "10.0.0.9", Response: map[string]any{"code": nextCode(t, seed)}})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(done.Status, session.StatusActive))

	// The earlier failure still counts against the IP: one more exhausts it.
	_, err = a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Password: "wrong", IP: "10.0.0.9"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	_, err = a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", IP: "10.0.0.9"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))
}

func TestMFAEnrollSuccessDoesNotResetIPThrottle(t *testing.T) {
	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a := newGrantsTestAuth(t, cfg, []Option{MFAStore(mfa.NewMemoryStore())}, mfaClient(client.MFAPolicyOptional))

	first := loginAs(t, a, alice(""))

	data, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: first.AccessToken, Method: totp.DriverName})
	qt.Assert(t, qt.IsNil(err))

	seed, _ := data["secret"].(string)

	_, err = a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: first.AccessToken, Method: totp.DriverName, IP: "10.0.0.9", Response: map[string]any{"code": "000000"}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	code, err := totp.GenerateCode(seed, time.Now())
	qt.Assert(t, qt.IsNil(err))

	_, err = a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: first.AccessToken, Method: totp.DriverName, IP: "10.0.0.9", Response: map[string]any{"code": code}})
	qt.Assert(t, qt.IsNil(err))

	_, err = a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "bob", Password: "wrong", IP: "10.0.0.9"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	_, err = a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", IP: "10.0.0.9"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))
}

func TestRecoveryCodesAreSingleUse(t *testing.T) {
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyOptional), mfa.NewMemoryStore())

	first := loginAs(t, a, alice(""))
	enrollTOTP(t, a, first.AccessToken)

	data, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: first.AccessToken, Method: "recovery"})
	qt.Assert(t, qt.IsNil(err))

	codes, _ := data["codes"].([]string)
	qt.Assert(t, qt.HasLen(codes, 10))

	_, err = a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: first.AccessToken, Method: "recovery"})
	qt.Assert(t, qt.IsNil(err))

	res := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(res.Status, session.StatusPendingMFA))

	_, err = a.BeginMFA(context.Background(), MFAStepRequest{Token: res.StepToken, Method: "recovery"})
	qt.Assert(t, qt.IsNil(err))

	done, err := a.VerifyMFA(context.Background(), MFAStepRequest{Token: res.StepToken, Response: map[string]any{"code": codes[0]}})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))

	// The same code cannot be replayed.
	again := loginAs(t, a, alice(""))
	_, err = a.BeginMFA(context.Background(), MFAStepRequest{Token: again.StepToken, Method: "recovery"})
	qt.Assert(t, qt.IsNil(err))
	_, err = a.VerifyMFA(context.Background(), MFAStepRequest{Token: again.StepToken, Response: map[string]any{"code": codes[0]}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))

	done2, err := a.VerifyMFA(context.Background(), MFAStepRequest{Token: again.StepToken, Response: map[string]any{"code": codes[1]}})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done2.Status, session.StatusActive))
}

// acrLadder is a two-rung ladder: loa1 = any login, loa2 = MFA passed.
func acrLadder() []contract.ACRLevelConfig {
	return []contract.ACRLevelConfig{
		{Value: "loa1", Level: 1},
		{Value: "loa2", Level: 2, RequireMFA: true, MFASatisfiedByAMR: []string{"hwk"}},
	}
}

func TestACRResolutionAndSatisfiedLevel(t *testing.T) {
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyDisabled), mfa.NewMemoryStore())
	a.Config().ACRLevels = acrLadder()

	// No request: lowest level.
	res := loginAs(t, a, alice(""))
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))
	qt.Check(t, qt.Equals(res.ACR, "loa1"))

	// A voluntary loa2 request with no enrollment onboards the user.
	setup := loginAs(t, a, alice("loa2"))
	qt.Check(t, qt.Equals(setup.Status, session.StatusPendingMFASetup))

	seed := enrollTOTP(t, a, res.AccessToken)

	// Requesting loa2 now prompts for MFA even though the client policy is disabled.
	pending := loginAs(t, a, alice("loa2"))
	qt.Assert(t, qt.Equals(pending.Status, session.StatusPendingMFA))

	done, err := a.VerifyMFA(context.Background(), MFAStepRequest{Token: pending.StepToken, Response: map[string]any{"code": nextCode(t, seed)}})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))
	qt.Check(t, qt.Equals(done.ACR, "loa2"))

	// Unknown values are ignored for a voluntary request, falling back to the lowest level.
	res2 := loginAs(t, a, alice("loa9"))
	qt.Check(t, qt.Equals(res2.Status, session.StatusActive))
	qt.Check(t, qt.Equals(res2.ACR, "loa1"))
}

func TestACRDefaultAndMinACR(t *testing.T) {
	cl := mfaClient(client.MFAPolicyDisabled)
	cl.MinACR = "loa2"

	// Without an MFA store the floor is unreachable: fail closed.
	noMFA := newServiceTestAuth(t, cl)
	noMFA.Config().ACRLevels = acrLadder()

	_, err := noMFA.Login(context.Background(), alice(""))
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnmetAuthenticationRequirements))

	// With a store the floor drives MFA onboarding even without acr_values.
	a := newMFATestAuth(t, cl, mfa.NewMemoryStore())
	a.Config().ACRLevels = acrLadder()

	res := loginAs(t, a, alice(""))
	qt.Check(t, qt.Equals(res.Status, session.StatusPendingMFASetup))

	// An acr_values entry below the floor is ignored.
	res = loginAs(t, a, alice("loa1"))
	qt.Check(t, qt.Equals(res.Status, session.StatusPendingMFASetup))
}

func TestACREssentialClaimsFailClosed(t *testing.T) {
	cl := mfaClient(client.MFAPolicyDisabled)
	cl.AllowedACRValues = []string{"loa1"}
	a := newMFATestAuth(t, cl, mfa.NewMemoryStore())
	a.Config().ACRLevels = acrLadder()

	// Voluntary: loa2 is not allowed for this client, so it falls back to loa1.
	res := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", ACRValues: "loa2"})
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))
	qt.Check(t, qt.Equals(res.ACR, "loa1"))

	// Essential: the same request is a hard failure.
	_, err := a.Login(context.Background(), LoginRequest{
		Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123",
		Claims: `{"id_token":{"acr":{"essential":true,"values":["loa2"]}}}`,
	})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnmetAuthenticationRequirements))
}

func TestACRMFASatisfiedByPrimaryAMR(t *testing.T) {
	cl := mfaClient(client.MFAPolicyRequired)
	a := newMFATestAuth(t, cl, mfa.NewMemoryStore())
	a.Config().ACRLevels = acrLadder()

	// The user provider asserts a hardware-key login; loa2 accepts "hwk" as multi-factor.
	users := a.users.(fakeUsers)
	u := users.users["alice"]
	u.AMR = []string{"hwk"}
	users.users["alice"] = u

	res := loginAs(t, a, alice("loa2"))
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))
	qt.Check(t, qt.Equals(res.ACR, "loa2"))
	qt.Check(t, qt.DeepEquals(res.AMR, []string{"pwd", "hwk"}))
}

func TestParseACRRequest(t *testing.T) {
	req := parseACRRequest("loa1 loa2", "")
	qt.Check(t, qt.DeepEquals(req.Values, []string{"loa1", "loa2"}))
	qt.Check(t, qt.IsFalse(req.Essential))

	req = parseACRRequest("loa1", `{"id_token":{"acr":{"essential":true,"value":"loa2"}}}`)
	qt.Check(t, qt.DeepEquals(req.Values, []string{"loa2"}))
	qt.Check(t, qt.IsTrue(req.Essential))

	req = parseACRRequest("loa1", `not json`)
	qt.Check(t, qt.DeepEquals(req.Values, []string{"loa1"}))
}

func TestAuthorizeEnforcesACROnEstablishedSession(t *testing.T) {
	portal := mfaClient(client.MFAPolicyDisabled)
	web := &client.Client{
		ID: "web", GrantTypes: []string{client.GrantTypeAuthorizationCode},
		RedirectURIs: []string{"https://web.example/cb"}, ResponseMode: client.ResponseModeJSON,
	}

	a := newMFATestAuth(t, portal, mfa.NewMemoryStore())
	a.Config().ACRLevels = acrLadder()
	a.clients.(*client.MemoryRegistry).Add(web)

	res := loginAs(t, a, alice(""))

	base := AuthorizeRequest{
		ResponseType: "code", ClientID: "web", RedirectURI: "https://web.example/cb", State: "s",
		CodeChallenge: pkceChallenge, CodeChallengeMethod: "S256", SessionToken: res.Cookie.Value,
	}

	// Voluntary loa2 is not met but the flow proceeds.
	out, err := a.Authorize(context.Background(), func() AuthorizeRequest { r := base; r.ACRValues = "loa2"; return r }())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(out.Redirect, "code="))

	// Essential loa2 redirects back with unmet_authentication_requirements.
	out, err = a.Authorize(context.Background(), func() AuthorizeRequest {
		r := base
		r.Claims = `{"id_token":{"acr":{"essential":true,"values":["loa2"]}}}`

		return r
	}())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(out.Redirect, "error=unmet_authentication_requirements"))

	// A client floor the session does not meet is refused the same way.
	web.MinACR = "loa2"
	a.clients.(*client.MemoryRegistry).Add(web)

	out, err = a.Authorize(context.Background(), base)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(out.Redirect, "error=unmet_authentication_requirements"))
}

func TestPendingSessionCookieDrivesStepInRedirectMode(t *testing.T) {
	cl := &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword}, AllowedAuthMethods: []string{client.AuthMethodPassword},
		ResponseMode: client.ResponseModeRedirect, MFAPolicy: client.MFAPolicyOptional, StepRedirectURI: "/mfa",
	}
	store := mfa.NewMemoryStore()
	a := newMFATestAuth(t, cl, store)

	qt.Assert(t, qt.IsNil(store.Enroll(context.Background(), &mfa.Enrollment{ID: "phone", UserID: "u1", Method: "push", Secret: []byte("phone")})))

	res := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123", ReturnTo: "/home"})
	qt.Assert(t, qt.Equals(res.Status, session.StatusPendingMFA))
	qt.Check(t, qt.Equals(res.ReturnTo, "/mfa?return_to=%2Fhome"))
	qt.Assert(t, qt.IsNotNil(res.Cookie))

	// The pending session cookie stands in for the step token.
	approvePush(t, a, "u1")

	done, err := a.MFAStatus(context.Background(), MFAStepRequest{Token: res.Cookie.Value, ReturnTo: "/home"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))
	qt.Check(t, qt.Equals(done.ReturnTo, "/home"))
	qt.Assert(t, qt.IsNotNil(done.Cookie))

	_, _, err = a.IntrospectToken(context.Background(), done.Cookie.Value)
	qt.Check(t, qt.IsNil(err))
}

func TestExternalLoginAMRSkipsMFA(t *testing.T) {
	cl := &client.Client{ID: "spa", GrantTypes: []string{client.GrantTypePassword}, ResponseMode: client.ResponseModeJSON, MFAPolicy: client.MFAPolicyRequired}
	store := mfa.NewMemoryStore()

	a := newExternalTestAuth(t, []contract.ExternalProviderConfig{
		{Name: "corp", Driver: "fake", ClientID: "c", RedirectURL: "https://issuer.example/auth/external/corp/callback"},
	}, nil, cl, MFAStore(store), ClaimMapping(ClaimMapperFunc(func(_ context.Context, _ string, raw map[string]any) (UserInfo, error) {
		sub, _ := raw["sub"].(string)

		return UserInfo{ID: sub, Scope: "openid", AMR: []string{"mfa"}}, nil
	})))
	a.Config().ACRLevels = []contract.ACRLevelConfig{{Value: "loa2", Level: 2, RequireMFA: true, MFASatisfiedByAMR: []string{"mfa"}}}

	begin, err := a.BeginExternalLogin(context.Background(), ExternalLoginRequest{Provider: "corp", ClientID: "spa"})
	qt.Assert(t, qt.IsNil(err))

	state := stateOf(t, begin.Redirect)

	out, err := a.ExternalCallback(context.Background(), ExternalCallbackRequest{Provider: "corp", State: state, Binding: begin.Cookie.Value, Code: "c1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(out.Login))
	qt.Check(t, qt.Equals(out.Login.Status, session.StatusActive))
	qt.Check(t, qt.Equals(out.Login.ACR, "loa2"))
	qt.Check(t, qt.DeepEquals(out.Login.AMR, []string{"mfa"}))
}

// stateOf extracts the state query parameter from an IdP redirect.
func stateOf(t *testing.T, redirect string) string {
	t.Helper()

	u, err := url.Parse(redirect)
	qt.Assert(t, qt.IsNil(err))

	return u.Query().Get("state")
}

func TestMFAEnrollRejectsThirdPartyAccessToken(t *testing.T) {
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyOptional), mfa.NewMemoryStore())
	at := thirdPartyAccessToken(t, a, loginAs(t, a, alice("")).Cookie.Value)

	_, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: at, Method: totp.DriverName})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientScope))

	qt.Check(t, qt.Equals(oauthErrorCode(t, a.RevokeMFA(context.Background(), at, totp.DriverName)), ErrCodeInsufficientScope))

	_, err = a.ListMFAMethods(context.Background(), at)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientScope))
}

func TestLoginRequiredMFANeverOnboardsEnrolledUser(t *testing.T) {
	store := mfa.NewMemoryStore()
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyOptional), store)
	enrollTOTP(t, a, loginAs(t, a, alice("")).AccessToken)

	// A client permitting only push must not let a password holder enroll a fresh factor.
	cl := mfaClient(client.MFAPolicyRequired)
	cl.AllowedMFAMethods = []string{mfatest.DriverName}

	_, err := newMFATestAuth(t, cl, store).Login(context.Background(), alice(""))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnmetAuthenticationRequirements))

	// The same holds for a level floor whose MFAMethods exclude the enrolled factor.
	floor := mfaClient(client.MFAPolicyDisabled)
	floor.MinACR = "loa2"
	c := newMFATestAuth(t, floor, store)
	c.Config().ACRLevels = []contract.ACRLevelConfig{{Value: "loa2", Level: 2, RequireMFA: true, MFAMethods: []string{mfatest.DriverName}}}

	_, err = c.Login(context.Background(), alice(""))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnmetAuthenticationRequirements))
}

func TestMFASwitchingBackReopensUnderResendLimits(t *testing.T) {
	store := mfa.NewMemoryStore()
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyOptional), store)

	first := loginAs(t, a, alice(""))
	seed := enrollTOTP(t, a, first.AccessToken)
	verified := verifyTOTP(t, a, loginAs(t, a, alice("")), seed)

	_, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: verified.AccessToken, Method: "push"})
	qt.Assert(t, qt.IsNil(err))
	_, err = a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: verified.AccessToken, Method: "push", Response: map[string]any{"device": "phone-1"}})
	qt.Assert(t, qt.IsNil(err))

	res := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(res.Selected, totp.DriverName))

	// The first push is issued freely, and TOTP issues nothing so it is never limited...
	_, err = a.BeginMFA(context.Background(), MFAStepRequest{Token: res.StepToken, Method: "push"})
	qt.Assert(t, qt.IsNil(err))
	_, err = a.BeginMFA(context.Background(), MFAStepRequest{Token: res.StepToken, Method: totp.DriverName})
	qt.Assert(t, qt.IsNil(err))

	// ...but switching back to push re-issues it, which is a resend under the cooldown.
	_, err = a.BeginMFA(context.Background(), MFAStepRequest{Token: res.StepToken, Method: "push"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))
}

func TestMFAVerifyBudgetHoldsAcrossConcurrentGuesses(t *testing.T) {
	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 3, Window: time.Minute, LockoutTTL: time.Minute}

	a := newGrantsTestAuth(t, cfg, []Option{MFAStore(mfa.NewMemoryStore())}, mfaClient(client.MFAPolicyOptional))
	enrollTOTP(t, a, loginAs(t, a, alice("")).AccessToken)

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Status, session.StatusPendingMFA))

	codes := make(chan ErrorCode, 20)

	var wg sync.WaitGroup

	for range 20 {
		wg.Go(func() {
			_, err := a.VerifyMFA(context.Background(), MFAStepRequest{Token: pending.StepToken, Response: map[string]any{"code": "000000"}})
			codes <- oauthErrorCode(t, err)
		})
	}

	wg.Wait()
	close(codes)

	evaluated := 0

	for code := range codes {
		if code == ErrCodeInvalidGrant {
			evaluated++
		} else {
			qt.Check(t, qt.Equals(code, ErrCodeSlowDown))
		}
	}

	// Every guess claims its attempt before the code is checked, so the budget holds even
	// when all of them arrive at once.
	qt.Check(t, qt.Equals(evaluated, cfg.Throttle.MaxAttempts))
}

func TestMFAChallengeOpensAreBoundedPerUserAcrossLogins(t *testing.T) {
	cfg := validConfig()
	cfg.LogoutInvalidatesCookie = true
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a := newGrantsTestAuth(t, cfg, []Option{MFAStore(mfa.NewMemoryStore())}, mfaClient(client.MFAPolicyOptional))
	active := loginAs(t, a, alice(""))

	_, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: active.AccessToken, Method: "push"})
	qt.Assert(t, qt.IsNil(err))
	_, err = a.FinishMFAEnroll(context.Background(), MFAEnrollRequest{Token: active.AccessToken, Method: "push", Response: map[string]any{"device": "phone-1"}})
	qt.Assert(t, qt.IsNil(err))

	// Every login pushes a challenge; abandoned logins count against the per-user limit.
	var last LoginResult
	for range a.Config().Throttle.MaxAttempts {
		last = loginAs(t, a, alice(""))
	}

	_, err = a.Login(context.Background(), alice(""))
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))

	// An approved challenge resets the counter.
	approvePush(t, a, "u1")

	done, err := a.MFAStatus(context.Background(), MFAStepRequest{Token: last.StepToken})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))
	qt.Check(t, qt.Equals(loginAs(t, a, alice("")).Status, session.StatusPendingMFA))
}

// assertedAMRAuth builds an Auth whose user provider asserts amr on every login, on a client
// that never prompts for a second factor.
func assertedAMRAuth(t *testing.T, store mfa.Store, amr []string) *Auth {
	t.Helper()

	cfg := validConfig()
	cfg.LogoutInvalidatesCookie = true

	users := fakeUsers{
		users:     map[string]UserInfo{"alice": {ID: "u1", Name: "Alice", Scope: "openid profile", AMR: amr}},
		passwords: map[string]string{"alice": "secret123"},
	}

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(),
		client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)), MFAStore(store))
	qt.Assert(t, qt.IsNil(err))

	return a
}

func TestFactorAdministrationIgnoresUnconfiguredAMR(t *testing.T) {
	store := mfa.NewMemoryStore()

	// Enroll a factor the asserted session never passes.
	seeded := newMFATestAuth(t, mfaClient(client.MFAPolicyDisabled), store)
	enrollTOTP(t, seeded, loginAs(t, seeded, alice("")).AccessToken)

	a := assertedAMRAuth(t, store, []string{"mfa"})

	// The session is active and carries amr "mfa", but no level was configured to accept it,
	// so it must not unlock factor administration.
	tok := loginAs(t, a, alice("")).AccessToken
	qt.Check(t, qt.Equals(oauthErrorCode(t, a.RevokeMFA(context.Background(), tok, totp.DriverName)), ErrCodeUnmetAuthenticationRequirements))

	_, err := a.BeginMFAEnroll(context.Background(), MFAEnrollRequest{Token: tok, Method: "push"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeUnmetAuthenticationRequirements))

	// Configuring a level to accept the value makes the trust explicit, and it then applies.
	a.Config().ACRLevels = []contract.ACRLevelConfig{{Value: "loa2", Level: 2, RequireMFA: true, MFASatisfiedByAMR: []string{"mfa"}}}

	res := loginAs(t, a, alice("loa2"))
	qt.Assert(t, qt.Equals(res.Status, session.StatusActive))
	qt.Check(t, qt.Equals(res.ACR, "loa2"))
	qt.Check(t, qt.IsNil(a.RevokeMFA(context.Background(), res.AccessToken, totp.DriverName)))
}

func TestLoginLockoutOutlivesTheCountingWindow(t *testing.T) {
	cfg := validConfig()
	cfg.LogoutInvalidatesCookie = true
	cfg.Throttle = contract.ThrottleConfig{
		Enabled: true, MaxAttempts: 2, Window: 50 * time.Millisecond, LockoutTTL: time.Hour,
	}

	a := newGrantsTestAuth(t, cfg, nil, portalClient())

	bad := LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "wrong", IP: "10.0.0.7"}

	for range 2 {
		_, err := a.Login(context.Background(), bad)
		qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidGrant))
	}

	// The counting window rolls over, but the lockout keeps the account blocked.
	time.Sleep(80 * time.Millisecond)

	_, err := a.Login(context.Background(), bad)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))

	good := bad
	good.Password = "secret123"

	_, err = a.Login(context.Background(), good)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))
}

func TestBrowserLogoutWithoutTokenClearsNoCookie(t *testing.T) {
	a := newMFATestAuth(t, mfaClient(client.MFAPolicyOptional), mfa.NewMemoryStore())

	// A cross-site navigation carries no cookie; the response must not clear one either.
	res, err := a.BrowserLogout(context.Background(), BrowserLogoutRequest{})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNil(res.ClearCookie))
	qt.Check(t, qt.Equals(res.Redirect, "/"))
}
