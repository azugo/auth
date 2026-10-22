package auth

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
)

// agreementStep holds a session until the user accepted the current agreement version.
type agreementStep struct {
	mu       sync.Mutex
	version  string
	accepted map[string]string
	// tenant limits the step to sessions of that tenant when set.
	tenant string
	// prompted records the session ID of every prompt.
	prompted []string
	// promptErr fails every prompt when set.
	promptErr error
}

func newAgreementStep(version string) *agreementStep {
	return &agreementStep{version: version, accepted: map[string]string{}}
}

func (s *agreementStep) Name() string {
	return "agreement"
}

func (s *agreementStep) Required(_ context.Context, sess *session.Session, _ UserInfo) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.tenant != "" && sess.Context["tenant"] != s.tenant {
		return false, nil
	}

	return s.accepted[sess.UserID] != s.version, nil
}

func (s *agreementStep) Prompt(_ context.Context, sess *session.Session, _ UserInfo) (StepPrompt, error) {
	s.mu.Lock()
	s.prompted = append(s.prompted, sess.ID)
	err := s.promptErr
	s.mu.Unlock()

	if err != nil {
		return StepPrompt{}, err
	}

	return StepPrompt{Interaction: "accept_agreement", Data: map[string]any{"version": s.version}}, nil
}

func (s *agreementStep) Resolve(_ context.Context, sess *session.Session, _ UserInfo, payload []byte) (StepResult, error) {
	var in struct {
		Accept string `json:"accept"`
	}

	if err := json.Unmarshal(payload, &in); err != nil {
		return StepResult{}, err
	}

	if in.Accept != s.version {
		return StepResult{Data: map[string]any{"error": "version_mismatch"}}, nil
	}

	s.mu.Lock()
	s.accepted[sess.UserID] = in.Accept
	s.mu.Unlock()

	sess.Context["agreement"] = in.Accept

	return StepResult{Done: true}, nil
}

// tenantStep asks for a tenant selection on every login and switches between tenants.
type tenantStep struct {
	tenants []string
	mode    SwitchMode
}

func (s *tenantStep) Name() string {
	return "tenant"
}

// Required always holds, so only the resolved list keeps it from prompting again.
func (s *tenantStep) Required(context.Context, *session.Session, UserInfo) (bool, error) {
	return true, nil
}

func (s *tenantStep) Prompt(context.Context, *session.Session, UserInfo) (StepPrompt, error) {
	return StepPrompt{Interaction: "select_tenant", Data: map[string]any{"tenants": s.tenants}}, nil
}

func (s *tenantStep) Resolve(_ context.Context, sess *session.Session, _ UserInfo, payload []byte) (StepResult, error) {
	var in map[string]any
	if err := json.Unmarshal(payload, &in); err != nil {
		return StepResult{}, err
	}

	tenant, _ := in["tenant"].(string)
	if !slices.Contains(s.tenants, tenant) {
		return StepResult{}, nil
	}

	sess.Context["tenant"] = tenant

	return StepResult{Done: true}, nil
}

func (s *tenantStep) Switch(_ context.Context, sess *session.Session, selection map[string]any) (SwitchMode, error) {
	tenant, _ := selection["tenant"].(string)
	if !slices.Contains(s.tenants, tenant) {
		return s.mode, ErrInvalidSelection
	}

	sess.Context["tenant"] = tenant

	return cmp.Or(s.mode, SwitchRotate), nil
}

func resolveStep(t *testing.T, a *Auth, pending LoginResult, name, payload string) LoginResult {
	t.Helper()

	res, err := a.ResolveStep(context.Background(), StepRequest{Token: pending.StepToken, Name: name, Payload: []byte(payload)})
	qt.Assert(t, qt.IsNil(err))

	return res
}

func TestPendingLoginOutlivesAShortAccessToken(t *testing.T) {
	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(newAgreementStep("v1")))
	a.Config().AccessTokenTTL = 5 * time.Minute

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Status, session.StatusPendingStep))

	// A login waiting on its steps lasts PendingTTL, not the access token's lifetime.
	claims, err := a.codec.DecodeSession(pending.StepToken)
	qt.Assert(t, qt.IsNil(err))

	expires := time.Until(time.Unix(claims.ExpiresAt, 0))
	qt.Check(t, qt.IsTrue(expires > 29*time.Minute && expires <= 30*time.Minute))
}

func TestLoginStepHoldsSessionUntilResolved(t *testing.T) {
	agreement := newAgreementStep("2026-01")
	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(agreement))

	pending := loginAs(t, a, alice(""))
	qt.Check(t, qt.Equals(pending.Status, session.StatusPendingStep))
	qt.Check(t, qt.Equals(pending.Step, "agreement"))
	qt.Check(t, qt.Equals(pending.Interaction, "accept_agreement"))
	qt.Check(t, qt.DeepEquals(pending.Data, map[string]any{"version": "2026-01"}))
	qt.Check(t, qt.Equals(pending.AccessToken, ""))
	qt.Assert(t, qt.IsTrue(pending.StepToken != ""))

	// A pending session is no access credential.
	_, _, err := a.IntrospectToken(context.Background(), pending.StepToken)
	qt.Check(t, qt.IsNotNil(err))

	// An unfinished submission stays pending with the follow-up merged into the prompt.
	retry := resolveStep(t, a, pending, "agreement", `{"accept":"2025-01"}`)
	qt.Check(t, qt.Equals(retry.Status, session.StatusPendingStep))
	qt.Check(t, qt.Equals(retry.StepToken, pending.StepToken))
	qt.Check(t, qt.DeepEquals(retry.Data, map[string]any{"version": "2026-01", "error": "version_mismatch"}))

	res := resolveStep(t, a, pending, "agreement", `{"accept":"2026-01"}`)
	qt.Assert(t, qt.Equals(res.Status, session.StatusActive))
	qt.Assert(t, qt.IsTrue(res.AccessToken != ""))

	info, sess, err := a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.Step, ""))
	qt.Check(t, qt.DeepEquals(info.Context, map[string]any{"agreement": "2026-01"}))

	// The step token is retired with the pending phase.
	_, err = a.ResolveStep(context.Background(), StepRequest{Token: pending.StepToken, Name: "agreement", Payload: []byte(`{}`)})
	qt.Check(t, qt.IsNotNil(err))

	// Accepted once, the next login is not held.
	qt.Check(t, qt.Equals(loginAs(t, a, alice("")).Status, session.StatusActive))
}

func TestLoginStepsRunInOrderAndResolveOnce(t *testing.T) {
	tenants := &tenantStep{tenants: []string{"acme", "globex"}}
	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(tenants, newAgreementStep("v1")))

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Step, "tenant"))
	qt.Check(t, qt.DeepEquals(pending.Data, map[string]any{"tenants": []string{"acme", "globex"}}))

	// Only the pending step may be resolved.
	_, err := a.ResolveStep(context.Background(), StepRequest{Token: pending.StepToken, Name: "agreement", Payload: []byte(`{"accept":"v1"}`)})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	_, err = a.ResolveStep(context.Background(), StepRequest{Token: pending.StepToken, Name: "unknown"})
	qt.Check(t, qt.Equals(err.(*OAuthError).StatusCode(), 404))

	// The tenant step always reports required, yet is not asked again in the same login.
	next := resolveStep(t, a, pending, "tenant", `{"tenant":"acme"}`)
	qt.Assert(t, qt.Equals(next.Status, session.StatusPendingStep))
	qt.Check(t, qt.Equals(next.Step, "agreement"))
	qt.Check(t, qt.IsTrue(next.StepToken != pending.StepToken))

	res := resolveStep(t, a, next, "agreement", `{"accept":"v1"}`)
	qt.Assert(t, qt.Equals(res.Status, session.StatusActive))

	info, _, err := a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(info.Context, map[string]any{"tenant": "acme", "agreement": "v1"}))
}

func TestLoginStepsComeAfterPasswordChange(t *testing.T) {
	a, _ := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(newAgreementStep("v1")))

	pending := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "fresh", Password: "changeme"})
	qt.Assert(t, qt.Equals(pending.Status, session.StatusPendingPasswordChange))

	next, err := a.ChangePassword(context.Background(), PasswordChangeRequest{Token: pending.StepToken, NewPassword: "a-new-password-1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(next.Status, session.StatusPendingStep))
	qt.Check(t, qt.Equals(next.Step, "agreement"))
}

func TestUnfinishedStepCountsAsFailedAttempt(t *testing.T) {
	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	users := fakeUsers{
		users:     map[string]UserInfo{"alice": {ID: "u1", Contacts: map[string][]Contact{ChannelEmail: {{Address: "alice@example.com"}}}, Scope: "openid"}},
		passwords: map[string]string{"alice": "secret123"},
	}

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)), LoginSteps(newAgreementStep("v1")))
	qt.Assert(t, qt.IsNil(err))

	pending := loginAs(t, a, alice(""))

	for range 2 {
		resolveStep(t, a, pending, "agreement", `{"accept":"v0"}`)
	}

	_, err = a.ResolveStep(context.Background(), StepRequest{Token: pending.StepToken, Name: "agreement", Payload: []byte(`{"accept":"v1"}`)})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))
}

func TestNewRejectsDuplicateLoginSteps(t *testing.T) {
	_, err := New(newApp(t), validConfig(), fakeUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry(),
		LoginSteps(newAgreementStep("v1"), newAgreementStep("v2")))
	qt.Check(t, qt.ErrorMatches(err, `duplicate login step "agreement"`))
}

func activeTenantSession(t *testing.T, a *Auth) LoginResult {
	t.Helper()

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Step, "tenant"))

	res := resolveStep(t, a, pending, "tenant", `{"tenant":"acme"}`)
	qt.Assert(t, qt.Equals(res.Status, session.StatusActive))

	return res
}

func TestSwitchSessionRotatesCredentials(t *testing.T) {
	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(&tenantStep{tenants: []string{"acme", "globex"}}))
	qt.Check(t, qt.IsTrue(a.SessionSwitching()))

	active := activeTenantSession(t, a)
	_, before, err := a.IntrospectToken(context.Background(), active.AccessToken)
	qt.Assert(t, qt.IsNil(err))

	_, err = a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.AccessToken, Selection: map[string]any{"tenant": "initech"}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	res, err := a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.AccessToken, Selection: map[string]any{"tenant": "globex"}})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(res.Status, session.StatusActive))
	qt.Check(t, qt.IsTrue(res.AccessToken != "" && res.AccessToken != active.AccessToken))

	// The presented credential is rotated out.
	_, _, err = a.IntrospectToken(context.Background(), active.AccessToken)
	qt.Check(t, qt.IsNotNil(err))

	info, after, err := a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(after.ID, before.ID))
	qt.Check(t, qt.DeepEquals(info.Context, map[string]any{"tenant": "globex"}))
	qt.Check(t, qt.IsTrue(after.ExpiresAt.Equal(before.ExpiresAt)))
}

func TestSwitchSessionRecreatesForHardIsolation(t *testing.T) {
	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(&tenantStep{tenants: []string{"acme", "globex"}, mode: SwitchRecreate}))

	active := activeTenantSession(t, a)
	_, before, err := a.IntrospectToken(context.Background(), active.AccessToken)
	qt.Assert(t, qt.IsNil(err))

	res, err := a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.Cookie.Value, Selection: map[string]any{"tenant": "globex"}})
	qt.Assert(t, qt.IsNil(err))

	_, after, err := a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(after.ID != before.ID))
	qt.Check(t, qt.IsTrue(after.CreatedAt.Equal(before.CreatedAt)))

	old, err := a.Sessions().Get(context.Background(), before.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(old.Valid()))
}

func TestSwitchRecreateAppliesOnceItsStepIsResolved(t *testing.T) {
	agreement := newAgreementStep("v1")
	agreement.tenant = "globex"

	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(&tenantStep{tenants: []string{"acme", "globex"}, mode: SwitchRecreate}, agreement))

	active := activeTenantSession(t, a)
	_, before, err := a.IntrospectToken(context.Background(), active.AccessToken)
	qt.Assert(t, qt.IsNil(err))

	// A failed prompt leaves nothing behind.
	agreement.mu.Lock()
	agreement.promptErr = errors.New("agreement service down")
	agreement.mu.Unlock()

	_, err = a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.AccessToken, Selection: map[string]any{"tenant": "globex"}})
	qt.Check(t, qt.IsNotNil(err))

	agreement.mu.Lock()
	agreement.promptErr = nil
	agreement.mu.Unlock()

	pending, err := a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.AccessToken, Selection: map[string]any{"tenant": "globex"}})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(pending.Step, "agreement"))

	// The step is prompted for the stored session, which exists.
	agreement.mu.Lock()
	prompted := slices.Clone(agreement.prompted)
	agreement.mu.Unlock()

	qt.Check(t, qt.DeepEquals(prompted, []string{before.ID, before.ID}))

	res := resolveStep(t, a, pending, "agreement", `{"accept":"v1"}`)
	qt.Assert(t, qt.Equals(res.Status, session.StatusActive))

	info, after, err := a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(after.ID != before.ID))
	qt.Check(t, qt.DeepEquals(info.Context, map[string]any{"tenant": "globex", "agreement": "v1"}))

	old, err := a.Sessions().Get(context.Background(), before.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(old.Valid()))
}

func TestSwitchWaitingOnAStepKeepsTheSession(t *testing.T) {
	agreement := newAgreementStep("v1")
	agreement.tenant = "globex"

	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(&tenantStep{tenants: []string{"acme", "globex"}}, agreement))

	active := activeTenantSession(t, a)
	_, before, err := a.IntrospectToken(context.Background(), active.AccessToken)
	qt.Assert(t, qt.IsNil(err))

	pending, err := a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.Cookie.Value, Selection: map[string]any{"tenant": "globex"}})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(pending.Step, "agreement"))
	qt.Check(t, qt.IsNil(pending.Cookie))

	// Until the step is resolved the session and its credentials stay as they were.
	stored, err := a.Sessions().Get(context.Background(), before.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(stored.Status, session.StatusActive))
	qt.Check(t, qt.IsTrue(stored.ExpiresAt.Equal(before.ExpiresAt)))

	info, _, err := a.IntrospectToken(context.Background(), active.Cookie.Value)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(info.Context, map[string]any{"tenant": "acme"}))

	// Only the step token is short-lived.
	claims, err := a.codec.DecodeSession(pending.StepToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(time.Unix(claims.ExpiresAt, 0).Before(before.ExpiresAt)))

	res := resolveStep(t, a, pending, "agreement", `{"accept":"v1"}`)
	qt.Assert(t, qt.Equals(res.Status, session.StatusActive))

	info, after, err := a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(after.ID, before.ID))
	qt.Check(t, qt.DeepEquals(info.Context, map[string]any{"tenant": "globex", "agreement": "v1"}))
	qt.Check(t, qt.IsTrue(after.ExpiresAt.Equal(before.ExpiresAt)))

	// The credential that asked for the switch is retired with it.
	_, _, err = a.IntrospectToken(context.Background(), active.Cookie.Value)
	qt.Check(t, qt.IsNotNil(err))
}

func TestSwitchKeepsSessionChangesMadeWhileItWaits(t *testing.T) {
	agreement := newAgreementStep("v1")
	agreement.tenant = "globex"

	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(&tenantStep{tenants: []string{"acme", "globex"}}, agreement))

	active := activeTenantSession(t, a)

	pending, err := a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.AccessToken, Selection: map[string]any{"tenant": "globex"}})
	qt.Assert(t, qt.IsNil(err))

	// A re-authentication lands on the stored session while the switch waits.
	_, stored, err := a.IntrospectToken(context.Background(), active.Cookie.Value)
	qt.Assert(t, qt.IsNil(err))

	reauthAt := time.Now().Add(time.Second).Truncate(time.Second)
	stored.AuthTime = reauthAt
	stored.AuthMFA = true
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), stored)))

	res := resolveStep(t, a, pending, "agreement", `{"accept":"v1"}`)
	qt.Assert(t, qt.Equals(res.Status, session.StatusActive))

	info, after, err := a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Context["tenant"], any("globex")))
	qt.Check(t, qt.IsTrue(after.AuthTime.Equal(reauthAt)))
	qt.Check(t, qt.IsTrue(after.AuthMFA))
}

func TestSwitchStepTokenIsNoSessionCredential(t *testing.T) {
	agreement := newAgreementStep("v1")
	agreement.tenant = "globex"

	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(&tenantStep{tenants: []string{"acme", "globex", "initech"}}, agreement))

	active := activeTenantSession(t, a)

	first, err := a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.Cookie.Value, Selection: map[string]any{"tenant": "globex"}})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(first.Step, "agreement"))

	// The step token resolves the step, but stands in for the session nowhere else.
	_, err = a.SwitchSession(context.Background(), SwitchSessionRequest{Token: first.StepToken, Selection: map[string]any{"tenant": "initech"}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))

	// A new switch replaces the waiting one and retires its step token.
	second, err := a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.Cookie.Value, Selection: map[string]any{"tenant": "globex"}})
	qt.Assert(t, qt.IsNil(err))

	_, err = a.ResolveStep(context.Background(), StepRequest{Token: first.StepToken, Name: "agreement", Payload: []byte(`{"accept":"v1"}`)})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))

	res := resolveStep(t, a, second, "agreement", `{"accept":"v1"}`)
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))
}

func TestFailedSwitchKeepsTheWaitingOne(t *testing.T) {
	agreement := newAgreementStep("v1")
	agreement.tenant = "globex"

	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(&tenantStep{tenants: []string{"acme", "globex"}}, agreement))

	active := activeTenantSession(t, a)

	waiting, err := a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.Cookie.Value, Selection: map[string]any{"tenant": "globex"}})
	qt.Assert(t, qt.IsNil(err))

	// A second switch that fails leaves the waiting one usable.
	agreement.mu.Lock()
	agreement.promptErr = errors.New("agreement service down")
	agreement.mu.Unlock()

	_, err = a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.Cookie.Value, Selection: map[string]any{"tenant": "globex"}})
	qt.Check(t, qt.IsNotNil(err))

	agreement.mu.Lock()
	agreement.promptErr = nil
	agreement.mu.Unlock()

	res := resolveStep(t, a, waiting, "agreement", `{"accept":"v1"}`)
	qt.Check(t, qt.Equals(res.Status, session.StatusActive))
}

func TestSwitchStepResolvesWithTheSessionCookie(t *testing.T) {
	agreement := newAgreementStep("v1")
	agreement.tenant = "globex"

	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(&tenantStep{tenants: []string{"acme", "globex"}}, agreement))

	active := activeTenantSession(t, a)

	_, err := a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.Cookie.Value, Selection: map[string]any{"tenant": "globex"}})
	qt.Assert(t, qt.IsNil(err))

	// A wrong answer keeps the switch pending and the cookie usable.
	res, err := a.ResolveStep(context.Background(), StepRequest{Token: active.Cookie.Value, Name: "agreement", Payload: []byte(`{"accept":"v0"}`)})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Status, session.StatusPendingStep))

	res, err = a.ResolveStep(context.Background(), StepRequest{Token: active.Cookie.Value, Name: "agreement", Payload: []byte(`{"accept":"v1"}`)})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(res.Status, session.StatusActive))

	info, _, err := a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Context["tenant"], any("globex")))
}

func TestSwitchSessionReentersRequiredStep(t *testing.T) {
	agreement := newAgreementStep("v1")
	agreement.tenant = "globex"

	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(&tenantStep{tenants: []string{"acme", "globex"}}, agreement))

	active := activeTenantSession(t, a)
	_, before, err := a.IntrospectToken(context.Background(), active.AccessToken)
	qt.Assert(t, qt.IsNil(err))

	pending, err := a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.AccessToken, Selection: map[string]any{"tenant": "globex"}})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(pending.Status, session.StatusPendingStep))
	qt.Check(t, qt.Equals(pending.Step, "agreement"))
	qt.Check(t, qt.Equals(pending.Interaction, "accept_agreement"))

	res := resolveStep(t, a, pending, "agreement", `{"accept":"v1"}`)
	qt.Assert(t, qt.Equals(res.Status, session.StatusActive))

	info, after, err := a.IntrospectToken(context.Background(), res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(info.Context, map[string]any{"tenant": "globex", "agreement": "v1"}))

	// Resolving a switch's step does not extend the session.
	qt.Check(t, qt.IsTrue(after.ExpiresAt.Equal(before.ExpiresAt)))
}

func TestSwitchSessionRequiresSwitcher(t *testing.T) {
	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(newAgreementStep("v1")))
	qt.Check(t, qt.IsFalse(a.SessionSwitching()))

	_, err := a.SwitchSession(context.Background(), SwitchSessionRequest{})
	qt.Check(t, qt.Equals(err.(*OAuthError).StatusCode(), 404))
}

func TestSessionContextReachesIDToken(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)

	cfg := validConfig()
	cfg.Keys = keySetConfig(priv, pub)

	users := fakeUsers{
		users:     map[string]UserInfo{"alice": {ID: "u1", Contacts: map[string][]Contact{ChannelEmail: {{Address: "alice@example.com"}}}, Scope: "openid"}},
		passwords: map[string]string{"alice": "secret123"},
	}

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)),
		LoginSteps(&tenantStep{tenants: []string{"acme"}}))
	qt.Assert(t, qt.IsNil(err))

	res := activeTenantSession(t, a)
	qt.Assert(t, qt.IsTrue(res.IDToken != ""))

	claims := decodeIDToken(t, res.IDToken, pub)
	qt.Check(t, qt.Equals(claims["tenant"], any("acme")))
	qt.Check(t, qt.Equals(claims["sub"], any("u1")))
}

// roleStep asks for a role per tenant and switches it on request.
type roleStep struct{}

func (roleStep) Name() string {
	return "role"
}

// Required holds while the chosen role belongs to another tenant than the selected one.
func (roleStep) Required(_ context.Context, sess *session.Session, _ UserInfo) (bool, error) {
	return sess.Context["role_tenant"] != sess.Context["tenant"], nil
}

func (roleStep) Prompt(context.Context, *session.Session, UserInfo) (StepPrompt, error) {
	return StepPrompt{Interaction: "select_role"}, nil
}

func (roleStep) Resolve(_ context.Context, sess *session.Session, _ UserInfo, payload []byte) (StepResult, error) {
	var in map[string]any
	if err := json.Unmarshal(payload, &in); err != nil {
		return StepResult{}, err
	}

	sess.Context["role"] = in["role"]
	sess.Context["role_tenant"] = sess.Context["tenant"]

	return StepResult{Done: true}, nil
}

func (roleStep) Switch(_ context.Context, sess *session.Session, selection map[string]any) (SwitchMode, error) {
	role, ok := selection["role"]
	if !ok {
		return SwitchSkip, nil
	}

	sess.Context["role"] = role
	sess.Context["role_tenant"] = sess.Context["tenant"]

	return SwitchRotate, nil
}

func TestSwitchSessionRechecksStepsTheSelectionSkipped(t *testing.T) {
	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(&tenantStep{tenants: []string{"acme", "globex"}}, roleStep{}))

	pending := loginAs(t, a, alice(""))
	pending = resolveStep(t, a, pending, "tenant", `{"tenant":"acme"}`)
	qt.Assert(t, qt.Equals(pending.Step, "role"))

	active := resolveStep(t, a, pending, "role", `{"role":"admin"}`)
	qt.Assert(t, qt.Equals(active.Status, session.StatusActive))

	// A selection no step applies changes nothing.
	_, err := a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.AccessToken, Selection: map[string]any{"colour": "red"}})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))

	// Switching only the tenant asks for the role again, as the acme role does not carry over.
	res, err := a.SwitchSession(context.Background(), SwitchSessionRequest{Token: active.AccessToken, Selection: map[string]any{"tenant": "globex"}})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Status, session.StatusPendingStep))
	qt.Check(t, qt.Equals(res.Step, "role"))
}

// flakyPromptStep fails its first prompt, as a throttled or unreachable channel would.
type flakyPromptStep struct {
	failed bool
}

func (*flakyPromptStep) Name() string {
	return "flaky"
}

func (*flakyPromptStep) Required(context.Context, *session.Session, UserInfo) (bool, error) {
	return true, nil
}

func (s *flakyPromptStep) Prompt(context.Context, *session.Session, UserInfo) (StepPrompt, error) {
	if !s.failed {
		s.failed = true

		return StepPrompt{}, NewThrottledError(time.Minute)
	}

	return StepPrompt{Interaction: "flaky"}, nil
}

func (*flakyPromptStep) Resolve(context.Context, *session.Session, UserInfo, []byte) (StepResult, error) {
	return StepResult{Done: true}, nil
}

func TestFailedPromptKeepsTheStepTokenUsable(t *testing.T) {
	a := newServiceTestAuth(t, mfaClient(client.MFAPolicyDisabled), LoginSteps(newAgreementStep("v1"), &flakyPromptStep{}))

	pending := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(pending.Step, "agreement"))

	// The next step cannot be prompted, so nothing is committed or retired.
	_, err := a.ResolveStep(context.Background(), StepRequest{Token: pending.StepToken, Name: "agreement", Payload: []byte(`{"accept":"v1"}`)})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeSlowDown))

	// The same step token can retry and move on.
	next := resolveStep(t, a, pending, "agreement", `{"accept":"v1"}`)
	qt.Check(t, qt.Equals(next.Step, "flaky"))
}
