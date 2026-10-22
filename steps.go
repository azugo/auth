package auth

import (
	"context"
	"errors"
	"maps"
	"net/url"
	"slices"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/event"
	"azugo.io/auth/mfa"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/core/cache"
	"azugo.io/core/http"
)

// ErrInvalidSelection is returned by a LoginStep or Switcher for a selection the user may not make.
var ErrInvalidSelection = errors.New("invalid selection")

// LoginStep is an application-defined gate that must be satisfied before a session becomes
// active.
type LoginStep interface {
	// Name identifies the step in URLs, in Session.Step and in the pending response.
	Name() string
	// Required reports whether the session must satisfy the step before activation.
	Required(ctx context.Context, s *session.Session, user UserInfo) (bool, error)
	// Prompt returns the interaction data the client renders to drive the step.
	Prompt(ctx context.Context, s *session.Session, user UserInfo) (StepPrompt, error)
	// Resolve processes the user's submission and may write the outcome into session context, which
	// is persisted only when the result is Done.
	Resolve(ctx context.Context, s *session.Session, user UserInfo, payload []byte) (StepResult, error)
}

// StepPrompt is the app-defined interaction descriptor surfaced to the client.
type StepPrompt struct {
	// Interaction is an app-defined hint, e.g. "select_tenant" or "accept_agreement".
	Interaction string
	// Data is the payload the client renders.
	Data map[string]any
}

// StepResult is result from resolve.
type StepResult struct {
	// Done clears the step; false keeps it pending and counts as a failed attempt.
	Done bool
	// NoAttempt keeps a pending result out of the throttle, for a submission that is no guess
	// such as a resend.
	NoAttempt bool
	// Data is merged into the prompt data when the step stays pending.
	Data map[string]any
}

// SwitchMode is how SwitchSession applies a new selection.
type SwitchMode int

const (
	// SwitchSkip leaves the step untouched, as the selection is not for it.
	SwitchSkip SwitchMode = iota
	// SwitchRotate keeps the session and rotates its credentials.
	SwitchRotate
	// SwitchRecreate replaces the session with a new one and revokes the old.
	SwitchRecreate
)

// Switcher is an optional LoginStep extension that applies a SwitchSession selection.
type Switcher interface {
	// Switch validates selection and writes it into session context, returning SwitchSkip when
	// the selection is not for this step.
	Switch(ctx context.Context, s *session.Session, selection map[string]any) (SwitchMode, error)
}

// LoginSteps registers the ordered application login steps.
func LoginSteps(steps ...LoginStep) Option {
	return func(a *Auth) {
		a.steps = append(a.steps, steps...)
	}
}

// StepRequest carries a submission for the pending login step behind Token.
type StepRequest struct {
	// Token is the step token (or the pending session cookie).
	Token string
	// Name is the login step the submission is for.
	Name string
	// Payload is passed to LoginStep.Resolve verbatim.
	Payload   []byte
	ReturnTo  string
	BaseURL   string
	MountPath string
	IP        string
}

// SwitchSessionRequest carries a new selection for the active session behind Token.
type SwitchSessionRequest struct {
	Token string
	// Selection is the app-defined choice applied by the Switcher steps.
	Selection map[string]any
	ReturnTo  string
	BaseURL   string
	MountPath string
	IP        string
}

// LoginSteps returns the registered login steps, the built-in ones first.
func (a *Auth) LoginSteps() []LoginStep {
	steps := make([]LoginStep, 0, len(a.contacts)+len(a.steps))
	for _, c := range a.contacts {
		steps = append(steps, c)
	}

	return append(steps, a.steps...)
}

// SessionSwitching reports whether any login step implements Switcher.
func (a *Auth) SessionSwitching() bool {
	return slices.ContainsFunc(a.steps, func(s LoginStep) bool {
		_, ok := s.(Switcher)

		return ok
	})
}

func (a *Auth) loginStep(name string) LoginStep {
	for _, s := range a.LoginSteps() {
		if s.Name() == name {
			return s
		}
	}

	return nil
}

// amrPassword is the RFC 8176 amr value recorded for a password login.
const amrPassword = "pwd"

// pendingState is the step state of a pending session, cached under its ID.
type pendingState struct {
	Initialized bool
	// TargetACR is the level the login must reach; Essential makes missing it a hard failure.
	TargetACR string
	Essential bool
	// Method and ChallengeID identify the active MFA challenge (pending_mfa); ChallengeData is
	// its prompt data, repeated on every poll.
	Method        string
	ChallengeID   string
	ChallengeData map[string]any
	// TokenIDs are the pending-phase credentials (cookie and step tokens), all retired once
	// the session activates.
	TokenIDs []string
	// Resolved are the login steps already resolved in this flow.
	Resolved []string
	// Switched is the context a SwitchSession applies once its steps are resolved, while the
	// stored session stays active on the previous selection; nil for a login.
	Switched map[string]any
	// SwitchStep is the step the switch waits on.
	SwitchStep string
	// Recreate makes applying the switch replace the session with a new one.
	Recreate bool
	// SwitchedBy is the credential that asked for the switch, retired once it applies.
	SwitchedBy string
}

// mfaEnrollment is the driver state of an in-progress enrollment.
type mfaEnrollment struct {
	State []byte
	// SessionID is the session that began the enrolment.
	SessionID string
}

// stepContext bundles a pending session with what the step endpoints need about it.
type stepContext struct {
	sess   *session.Session
	claims *token.AccessClaims
	client *client.Client
	state  pendingState
}

// loadUser fills info with user id unless an earlier call of the evaluation already did.
func (a *Auth) loadUser(ctx context.Context, id string, info *UserInfo) error {
	if info.ID != "" {
		return nil
	}

	loaded, err := a.users.GetUser(ctx, id)
	if err != nil {
		return err
	}

	*info = loaded

	return nil
}

// filterMethods returns the method names both the client and level permit.
func filterMethods(names []string, cl *client.Client, lvl *contract.ACRLevelConfig) []string {
	out := make([]string, 0, len(names))

	for _, n := range names {
		if len(cl.AllowedMFAMethods) > 0 && !slices.Contains(cl.AllowedMFAMethods, n) {
			continue
		}

		if lvl != nil && len(lvl.MFAMethods) > 0 && !slices.Contains(lvl.MFAMethods, n) {
			continue
		}

		out = append(out, n)
	}

	return out
}

// primaryMethods drops the backup methods from names.
func (a *Auth) primaryMethods(ctx context.Context, names []string) ([]string, error) {
	out := make([]string, 0, len(names))

	for _, name := range names {
		m, err := a.mfaMethods.Get(ctx, name)
		if err != nil {
			return nil, err
		}

		if !mfa.MethodBackup(m) {
			out = append(out, name)
		}
	}

	return out, nil
}

// mfaMethodSets returns the methods the client and target level permit.
func (a *Auth) mfaMethodSets(ctx context.Context, userID string, cl *client.Client, target *contract.ACRLevelConfig) ([]string, []string, error) {
	if a.mfaStore == nil {
		return nil, nil, nil
	}

	names, err := a.mfaMethods.Names(ctx)
	if err != nil {
		return nil, nil, err
	}

	enrolled, err := mfa.EnrolledMethods(ctx, a.mfaStore, userID)
	if err != nil {
		return nil, nil, err
	}

	permitted := filterMethods(names, cl, target)

	var available []string

	for _, m := range enrolled {
		if slices.Contains(permitted, m) {
			available = append(available, m)
		}
	}

	return permitted, available, nil
}

// evaluateSteps resolves the target ACR and the login steps for session, skipping the
// resolved login steps.
func (a *Auth) evaluateSteps(ctx context.Context, sess *session.Session, info *UserInfo, cl *client.Client, req acrRequest, resolved []string) (pendingState, error) {
	var names, primary, enrolled []string

	// The factors matter only when the client or a level can ask for one.
	if a.mfaStore != nil && (cl.MFAPolicy == client.MFAPolicyRequired || cl.MFAPolicy == client.MFAPolicyOptional ||
		slices.ContainsFunc(a.config.ACRLevels, func(lvl contract.ACRLevelConfig) bool { return lvl.RequireMFA })) {
		var err error

		if names, err = a.mfaMethods.Names(ctx); err != nil {
			return pendingState{}, err
		}

		// Only a primary method can be a user's first factor.
		if primary, err = a.primaryMethods(ctx, names); err != nil {
			return pendingState{}, err
		}

		if enrolled, err = mfa.EnrolledMethods(ctx, a.mfaStore, sess.UserID); err != nil {
			return pendingState{}, err
		}
	}

	// A level is reachable when already satisfied, or when only its MFA requirement is unmet
	// and a permitted factor is enrolled, or the user has no factor yet and may enroll one.
	reachable := func(lvl *contract.ACRLevelConfig) bool {
		if levelSatisfied(lvl, sess) {
			return true
		}

		if len(lvl.AuthMethods) > 0 && !slices.Contains(lvl.AuthMethods, primaryMethod(sess)) {
			return false
		}

		if !lvl.RequireMFA || sess.MFAMethod != "" {
			return false
		}

		return intersects(enrolled, filterMethods(names, cl, lvl)) || (len(enrolled) == 0 && len(filterMethods(primary, cl, lvl)) > 0)
	}

	target, err := a.resolveTargetACR(cl, req, reachable)
	if err != nil {
		return pendingState{}, err
	}

	st := pendingState{
		Initialized: true,
		Essential:   req.Essential,
		Resolved:    resolved,
	}
	if target != nil {
		st.TargetACR = target.Value
	}

	sess.Status = session.StatusActive
	sess.Step = ""

	// An unverified address is proven before a factor can be bound to the account.
	if err := evaluateGates(ctx, a, sess, info, a.contacts, resolved); err != nil || sess.Status != session.StatusActive {
		return st, err
	}

	required := cl.MFAPolicy == client.MFAPolicyRequired || (target != nil && target.RequireMFA)
	optional := cl.MFAPolicy == client.MFAPolicyOptional
	satisfied := sess.MFAMethod != "" || (target != nil && intersects(sess.AMR, target.MFASatisfiedByAMR))

	// A requirement nothing can satisfy fails closed rather than silently.
	if a.mfaStore == nil && required && !satisfied {
		return pendingState{}, ErrUnmetAuthenticationRequirements
	}

	if a.mfaStore != nil && !satisfied && (required || optional) {
		// Only a user without any factor is onboarded; an enrolled factor that the client or
		// level does not permit must not be bypassed by enrolling a new one.
		switch {
		case intersects(enrolled, filterMethods(names, cl, target)):
			sess.Status = session.StatusPendingMFA
		case required && len(enrolled) == 0 && len(filterMethods(primary, cl, target)) > 0:
			sess.Status = session.StatusPendingMFASetup
		case required:
			return pendingState{}, ErrUnmetAuthenticationRequirements
		}
	}

	if sess.Status != session.StatusActive {
		return st, nil
	}

	sess.ACR = a.satisfiedACR(sess)

	if target != nil && !levelSatisfied(target, sess) {
		return pendingState{}, ErrUnmetAuthenticationRequirements
	}

	// A forced password change is the last step, so only a login that passed every factor
	// may replace the credential
	if err := a.loadUser(ctx, sess.UserID, info); err != nil {
		return pendingState{}, err
	}

	if info.RequiresPasswordChange {
		if _, ok := a.users.(PasswordChanger); !ok {
			return pendingState{}, ErrPasswordChangeRequired
		}

		sess.Status = session.StatusPendingPasswordChange

		return st, nil
	}

	if err := evaluateGates(ctx, a, sess, info, a.steps, resolved); err != nil {
		return pendingState{}, err
	}

	return st, nil
}

// evaluateLoginGates holds session at the first contact or application step it still requires.
func (a *Auth) evaluateLoginGates(ctx context.Context, sess *session.Session, info *UserInfo, resolved []string) error {
	if err := evaluateGates(ctx, a, sess, info, a.contacts, resolved); err != nil || sess.Status != session.StatusActive {
		return err
	}

	return evaluateGates(ctx, a, sess, info, a.steps, resolved)
}

// evaluateGates holds session at the first of steps it still requires.
func evaluateGates[S LoginStep](ctx context.Context, a *Auth, sess *session.Session, info *UserInfo, steps []S, resolved []string) error {
	for _, step := range steps {
		if slices.Contains(resolved, step.Name()) {
			continue
		}

		if err := a.loadUser(ctx, sess.UserID, info); err != nil {
			return err
		}

		required, err := step.Required(ctx, sess, *info)
		if err != nil {
			return err
		}

		if required {
			sess.Status = session.StatusPendingStep
			sess.Step = step.Name()

			return nil
		}
	}

	return nil
}

// startSession resolves the login steps for a freshly authenticated sess, persists it and
// returns the final credentials when active or a step token when pending.
func (a *Auth) startSession(ctx context.Context, sess *session.Session, cl *client.Client, req acrRequest, returnTo string, baseURL, mountPath string) (LoginResult, error) {
	var info UserInfo

	st, err := a.evaluateSteps(ctx, sess, &info, cl, req, nil)
	if err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	now := time.Now()
	sess.CreatedAt = now
	sess.LastSeen = now
	sess.AuthTime = now
	sess.AuthMethods = sess.AMR
	sess.AuthACR = sess.ACR
	sess.AuthMFA = a.mfaVerified(sess)
	sess.ExpiresAt = now.Add(a.config.SessionTTL)

	// A pending session lives only as long as its step token.
	if sess.Status != session.StatusActive {
		sess.ExpiresAt = now.Add(a.config.PendingTTL)
	}

	cookie, jti, err := a.commitSession(ctx, sess, "", nil, now)
	if err != nil {
		return LoginResult{}, err
	}

	if sess.Status == session.StatusActive {
		return a.buildLoginResult(ctx, sess, cl, returnTo, cookie, baseURL, mountPath)
	}

	st.TokenIDs = append(st.TokenIDs, jti)

	prompt, err := a.promptPending(ctx, sess, &info, cl, &st)
	if err != nil {
		return LoginResult{}, err
	}

	return a.pendingLoginResult(ctx, sess, cl, st, prompt, cookie, returnTo, baseURL, mountPath)
}

// pendingLoginResult persists the step state, opens the first MFA challenge when needed and
// issues the step token for a pending session.
func (a *Auth) pendingLoginResult(ctx context.Context, sess *session.Session, cl *client.Client, st pendingState, res LoginResult, cookie, returnTo string, baseURL, mountPath string) (LoginResult, error) {
	res.Status = sess.Status
	res.ACR = sess.ACR
	res.AMR = sess.AMR

	if cookie != "" {
		res.Cookie = a.cookieDirective(cookie, time.Until(sess.ExpiresAt), baseURL, mountPath)
	}

	step, jti, err := a.issueStepToken(ctx, sess, cl)
	if err != nil {
		return LoginResult{}, err
	}

	st.TokenIDs = append(st.TokenIDs, jti)

	if err := setSynced(ctx, a.pending, sess.ID, st, cache.TTL[pendingState](time.Until(a.pendingUntil(sess)))); err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	res.StepToken = step

	if cl.ResponseMode == client.ResponseModeRedirect {
		res.ReturnTo = stepRedirect(cl, returnTo)
	}

	return res, nil
}

// promptPending builds the prompt of a pending session, opening its MFA challenge when needed;
// callers run it before retiring any credential, so a failure leaves the flow usable.
func (a *Auth) promptPending(ctx context.Context, sess *session.Session, info *UserInfo, cl *client.Client, st *pendingState) (LoginResult, error) {
	var res LoginResult

	switch sess.Status {
	case session.StatusPendingMFA:
		if err := a.selectMFA(ctx, sess, cl, st, &res, "", false); err != nil {
			return LoginResult{}, err
		}
	case session.StatusPendingStep:
		if err := a.promptStep(ctx, sess, info, &res); err != nil {
			return LoginResult{}, err
		}
	case session.StatusActive, session.StatusPendingPasswordChange, session.StatusPendingMFASetup:
	}

	return res, nil
}

// limitChallenge claims the right to issue another challenge for method within the pending
// flow id (a session or a reset request), counted for ttl. Re-issuing one is a resend whichever
// way it is reached, so it is capped and rate limited per flow, and every issue is bounded by
// the per-user budget key across flows so repeated attempts cannot flood a device. The returned
// release undoes the claim when nothing was issued.
func (a *Auth) limitChallenge(ctx context.Context, id, budget string, ttl time.Duration, clientID, method string) (func(), error) {
	counter := id + ":" + method

	// Counting before anything is issued keeps a failure to count from letting one through.
	issued, err := a.challenges.Increment(ctx, counter, 1, cache.TTL[int64](ttl))
	if err != nil {
		return nil, NewOAuthErrorFrom(err)
	}

	revert := func() {
		_, _ = a.challenges.Increment(ctx, counter, -1)
	}

	if issued > int64(a.config.Throttle.MFAMaxResends)+1 {
		revert()

		remaining, _, err := a.challenges.TTL(ctx, counter)
		if err != nil {
			return nil, NewOAuthErrorFrom(err)
		}

		if remaining <= 0 {
			remaining = ttl
		}

		return nil, NewThrottledError(remaining)
	}

	if err := a.checkThrottle(ctx, []string{budget}, clientID, ""); err != nil {
		revert()

		return nil, err
	}

	release := func() {
		revert()
		a.refundThrottle(ctx, []string{budget})
	}

	cooldown := a.config.Throttle.MFAResendCooldown
	if cooldown <= 0 {
		return release, nil
	}

	// Claiming is atomic and the marker's own lifetime is the cooldown, so its presence is
	// the answer and concurrent callers cannot both pass.
	key := "cooldown:" + id + ":" + method

	fresh, err := a.challenges.Add(ctx, key, 1, cache.TTL[int64](cooldown))
	if err != nil {
		release()

		return nil, NewOAuthErrorFrom(err)
	}

	if !fresh {
		release()

		remaining, _, err := a.challenges.TTL(ctx, key)
		if err != nil {
			return nil, NewOAuthErrorFrom(err)
		}

		if remaining <= 0 {
			remaining = cooldown
		}

		return nil, NewThrottledError(remaining)
	}

	return func() {
		release()

		_ = a.challenges.Delete(ctx, key)
	}, nil
}

// selectMFA fills the pending_mfa prompt on login result.
func (a *Auth) selectMFA(ctx context.Context, sess *session.Session, cl *client.Client, st *pendingState, res *LoginResult, method string, force bool) error {
	_, available, err := a.mfaMethodSets(ctx, sess.UserID, cl, a.acrLevel(st.TargetACR))
	if err != nil {
		return NewOAuthErrorFrom(err)
	}

	if len(available) == 0 {
		return NewOAuthErrorFrom(ErrUnmetAuthenticationRequirements)
	}

	if method == "" {
		method = st.Method
	}

	if method == "" {
		method = available[0]
	}

	if !slices.Contains(available, method) {
		return NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "mfa method is not available")
	}

	m, err := a.mfaMethods.Get(ctx, method)
	if err != nil {
		return NewOAuthErrorFrom(err)
	}

	if force || method != st.Method {
		challengeID, data, err := a.openMFAChallenge(ctx, sess.ID, sess.UserID, sess.ExpiresAt, cl.ID, method, m)
		if err != nil {
			return err
		}

		st.Method = method
		st.ChallengeID = challengeID
		st.ChallengeData = data
	}

	res.Data = st.ChallengeData
	res.Available = available
	res.Selected = method
	res.Interaction = mfa.MethodInteraction(m)

	return nil
}

// openMFAChallenge opens a challenge for method within flow id under the resend limits and the
// user's per-user budget.
func (a *Auth) openMFAChallenge(ctx context.Context, id, userID string, expiresAt time.Time, clientID, method string, m mfa.Method) (string, map[string]any, error) {
	budget := "mfa-open:" + userID

	release, err := a.limitChallenge(ctx, id, budget, time.Until(expiresAt), clientID, method)
	if err != nil {
		return "", nil, err
	}

	challengeID, data, err := m.BeginVerify(ctx, userID)

	// A self-contained method issues nothing and a failed one delivered nothing, so
	// neither counts against the limits and neither holds the cooldown.
	if challengeID == "" {
		release()
	}

	if err != nil {
		return "", nil, NewOAuthErrorFrom(err)
	}

	if challengeID != "" {
		a.failThrottle(ctx, []string{budget})
	}

	return challengeID, data, nil
}

// pendingUntil is when sess's pending phase and its step token end; a switched session outlives
// them.
func (a *Auth) pendingUntil(sess *session.Session) time.Time {
	until := time.Now().Add(a.config.PendingTTL)
	if sess.ExpiresAt.Before(until) {
		return sess.ExpiresAt
	}

	return until
}

// issueStepToken mints a step token bound to the pending sess, returning it with its jti.
func (a *Auth) issueStepToken(ctx context.Context, sess *session.Session, cl *client.Client) (string, string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", "", NewOAuthErrorFrom(err)
	}

	expiresAt := a.pendingUntil(sess)

	if err := a.jti.Issue(ctx, jti, sess.ID, time.Until(expiresAt)); err != nil {
		return "", "", NewOAuthErrorFrom(err)
	}

	tok, err := a.codec.Encrypt(token.AccessClaims{
		Type:      token.TypeStepToken,
		SessionID: sess.ID,
		TokenID:   jti,
		ClientID:  cl.ID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: expiresAt.Unix(),
	})
	if err != nil {
		return "", "", NewOAuthErrorFrom(err)
	}

	return tok, jti, nil
}

// stepRedirect builds the redirect-mode target for a pending login.
func stepRedirect(cl *client.Client, returnTo string) string {
	target := safeLocalRedirect(returnTo)
	if cl.StepRedirectURI == "" {
		return target
	}

	u, err := url.Parse(safeLocalRedirect(cl.StepRedirectURI))
	if err != nil {
		return target
	}

	q := u.Query()
	q.Set("return_to", target)
	u.RawQuery = q.Encode()

	return u.String()
}

// sessionClaims decodes any session-bound token (access, cookie or step) and loads its live
// session.
func (a *Auth) sessionClaims(ctx context.Context, tok string) (*token.AccessClaims, *session.Session, error) {
	if tok == "" {
		return nil, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	claims, err := a.codec.DecodeSession(tok)
	if err != nil {
		return nil, nil, NewOAuthErrorFrom(err)
	}

	if time.Now().Unix() >= claims.ExpiresAt {
		return nil, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	valid, err := a.jti.Validate(ctx, claims.TokenID, claims.SessionID)
	if err != nil {
		return nil, nil, NewOAuthErrorFrom(err)
	}

	if !valid {
		return nil, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	sess, err := a.sessions.Get(ctx, claims.SessionID)
	if err != nil {
		return nil, nil, NewOAuthErrorFrom(err)
	}

	if !sess.Valid() {
		return nil, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	if !firstParty(claims, sess) {
		return nil, nil, NewOAuthErrorFrom(ErrFirstPartyRequired)
	}

	return claims, sess, nil
}

// stepSession resolves a step token (or the pending session cookie) to its session in one of
// the given statuses, with its client and cached step state.
func (a *Auth) stepSession(ctx context.Context, tok string, statuses ...session.Status) (*stepContext, error) {
	claims, sess, err := a.sessionClaims(ctx, tok)
	if err != nil {
		return nil, err
	}

	cl, err := a.clients.GetClient(ctx, sess.ClientID)
	if err != nil {
		return nil, NewOAuthErrorFrom(err)
	}

	sc := &stepContext{sess: sess, claims: claims, client: cl}

	// A step token reaches an active session only through a switch waiting on its steps.
	if sess.Status == session.StatusActive && claims.Type != token.TypeStepToken && slices.Contains(statuses, session.StatusActive) {
		return sc, nil
	}

	st, err := a.pending.Get(ctx, sess.ID)
	if err != nil {
		if _, ok := errors.AsType[cache.KeyNotFoundError](err); ok {
			return nil, NewOAuthErrorFrom(token.ErrInvalidToken)
		}

		return nil, NewOAuthErrorFrom(err)
	}

	if !st.Initialized {
		return nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	// An active session is pending only through a switch waiting on its steps.
	if sess.Status == session.StatusActive {
		if st.Switched == nil {
			return nil, NewOAuthErrorFrom(token.ErrInvalidToken)
		}

		// The switch is laid over the stored session as it is now.
		switched := *sess
		switched.Context = st.Switched
		switched.Status = session.StatusPendingStep
		switched.Step = st.SwitchStep
		sc.sess = &switched
	}

	if !slices.Contains(statuses, sc.sess.Status) {
		return nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	sc.state = st

	return sc, nil
}

// advanceSession re-evaluates the login steps after one was satisfied and, once active,
// extends the session, retires the presented step token and issues the final credentials.
func (a *Auth) advanceSession(ctx context.Context, sc *stepContext, returnTo string, baseURL, mountPath string) (LoginResult, error) {
	sess := sc.sess

	req := acrRequest{Essential: sc.state.Essential}
	if sc.state.TargetACR != "" {
		req.Values = []string{sc.state.TargetACR}
	}

	var (
		info UserInfo
		st   pendingState
		err  error
	)

	// A switch re-checks only the login steps, as SwitchSession does.
	if sc.state.Switched != nil {
		st = pendingState{Initialized: true, TargetACR: sc.state.TargetACR, Resolved: sc.state.Resolved, Recreate: sc.state.Recreate, SwitchedBy: sc.state.SwitchedBy}
		sess.Status = session.StatusActive
		sess.Step = ""
		err = a.evaluateLoginGates(ctx, sess, &info, sc.state.Resolved)
	} else {
		st, err = a.evaluateSteps(ctx, sess, &info, sc.client, req, sc.state.Resolved)
	}

	if err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	now := time.Now()
	sess.LastSeen = now

	// Every pending-phase credential is retired, not only the presented one.
	retired := sc.state.TokenIDs
	if !slices.Contains(retired, sc.claims.TokenID) {
		retired = append(retired, sc.claims.TokenID)
	}

	// A session still pending after a step gets a fresh cookie and step token
	if sess.Status != session.StatusActive {
		prompt, err := a.promptPending(ctx, sess, &info, sc.client, &st)
		if err != nil {
			return LoginResult{}, err
		}

		// A switch keeps the stored session and its cookie until its steps are resolved.
		if sc.state.Switched != nil {
			st.TokenIDs = sc.state.TokenIDs

			if sc.claims.Type == token.TypeStepToken {
				if err := a.jti.Revoke(ctx, sc.claims.TokenID); err != nil {
					return LoginResult{}, NewOAuthErrorFrom(err)
				}

				st.TokenIDs = slices.DeleteFunc(slices.Clone(st.TokenIDs), func(id string) bool { return id == sc.claims.TokenID })
			}

			st.Switched = sess.Context
			st.SwitchStep = sess.Step

			return a.pendingLoginResult(ctx, sess, sc.client, st, prompt, "", returnTo, baseURL, mountPath)
		}

		cookie, jti, err := a.commitSession(ctx, sess, "", retired, now)
		if err != nil {
			return LoginResult{}, err
		}

		st.TokenIDs = []string{jti}

		return a.pendingLoginResult(ctx, sess, sc.client, st, prompt, cookie, returnTo, baseURL, mountPath)
	}

	if sc.state.Switched != nil {
		cookie, err := a.applySwitch(ctx, sess, sc.state.Recreate, append(retired, sc.state.SwitchedBy), "")
		if err != nil {
			return LoginResult{}, err
		}

		return a.buildLoginResult(ctx, sess, sc.client, returnTo, cookie, baseURL, mountPath)
	}

	// A step may have held the login before its level was known, so it is scored once complete.
	var mfaMethod string
	if sess.AuthMFA {
		mfaMethod = sess.MFAMethod
	}

	sess.AuthACR = a.authACR(primaryMethod(sess), sess.AuthMethods, mfaMethod)

	if lvl := a.acrLevel(sess.AuthACR); lvl != nil && intersects(sess.AuthMethods, lvl.MFASatisfiedByAMR) {
		sess.AuthMFA = true
	}

	sess.ExpiresAt = now.Add(a.config.SessionTTL)

	cookie, _, err := a.commitSession(ctx, sess, "", retired, now)
	if err != nil {
		return LoginResult{}, err
	}

	_ = deleteSynced(ctx, a.pending, sess.ID)

	a.emit(ctx, event.Event{Type: event.TypeLoginSuccess, UserID: sess.UserID, ClientID: sess.ClientID, Detail: map[string]any{"step": "completed"}})

	return a.buildLoginResult(ctx, sess, sc.client, returnTo, cookie, baseURL, mountPath)
}

// promptStep fills the pending_step prompt on login result.
func (a *Auth) promptStep(ctx context.Context, sess *session.Session, info *UserInfo, res *LoginResult) error {
	step := a.loginStep(sess.Step)
	if step == nil {
		return NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	if err := a.loadUser(ctx, sess.UserID, info); err != nil {
		return NewOAuthErrorFrom(err)
	}

	p, err := step.Prompt(ctx, sess, *info)
	if err != nil {
		return NewOAuthErrorFrom(err)
	}

	res.Step = sess.Step
	res.Interaction = p.Interaction
	res.Data = p.Data

	return nil
}

// ResolveStep submits a payload to the pending login step: a done step advances the session,
// otherwise the step stays pending as a throttled failed attempt.
func (a *Auth) ResolveStep(ctx context.Context, in StepRequest) (LoginResult, error) {
	step := a.loginStep(in.Name)
	if step == nil {
		return LoginResult{}, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "unknown login step")
	}

	sc, err := a.stepSession(ctx, in.Token, session.StatusPendingStep)
	if err != nil {
		return LoginResult{}, err
	}

	if sc.sess.Step != in.Name {
		return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "login step is not the pending one")
	}

	identity := "step:" + sc.sess.UserID
	keys := throttleKeys(identity, in.IP)

	if err := a.checkThrottle(ctx, keys, sc.client.ID, in.IP); err != nil {
		return LoginResult{}, err
	}

	// Resolve works on a copy so an unfinished step leaves nothing behind.
	work := *sc.sess
	work.Context = maps.Clone(sc.sess.Context)

	if work.Context == nil {
		work.Context = make(map[string]any)
	}

	// The step and the prompt that may follow share one load of the user.
	var info UserInfo

	if err := a.loadUser(ctx, work.UserID, &info); err != nil {
		a.refundThrottle(ctx, keys)

		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	r, err := step.Resolve(ctx, &work, info, in.Payload)
	if err != nil {
		a.refundThrottle(ctx, keys)

		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	detail := map[string]any{"step": in.Name}

	if !r.Done {
		if r.NoAttempt {
			a.refundThrottle(ctx, keys)
		} else {
			a.failThrottle(ctx, keys)
			a.emit(ctx, event.Event{Type: event.TypeStepFailure, UserID: sc.sess.UserID, ClientID: sc.client.ID, IP: in.IP, Detail: detail})
		}

		res := stepResult(sc, in.Token, in.ReturnTo)

		if err := a.promptStep(ctx, sc.sess, &info, &res); err != nil {
			return LoginResult{}, err
		}

		if len(r.Data) > 0 {
			data := maps.Clone(res.Data)
			if data == nil {
				data = make(map[string]any, len(r.Data))
			}

			maps.Copy(data, r.Data)
			res.Data = data
		}

		return res, nil
	}

	a.passThrottle(ctx, keys, identity)
	a.emit(ctx, event.Event{Type: event.TypeStepCompleted, UserID: sc.sess.UserID, ClientID: sc.client.ID, IP: in.IP, Detail: detail})

	sc.sess = &work
	sc.state.Resolved = append(sc.state.Resolved, in.Name)

	return a.advanceSession(ctx, sc, in.ReturnTo, in.BaseURL, in.MountPath)
}

// SwitchSession applies a new selection to an active session through the Switcher steps,
// re-evaluates the login steps and re-issues its credentials. When a step is required again it
// returns a step token instead and applies the selection only once the step is resolved.
func (a *Auth) SwitchSession(ctx context.Context, in SwitchSessionRequest) (LoginResult, error) {
	if !a.SessionSwitching() {
		return LoginResult{}, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "session switching is not enabled")
	}

	sc, err := a.stepSession(ctx, in.Token, session.StatusActive)
	if err != nil {
		return LoginResult{}, err
	}

	if err := a.checkStepUp(ctx, sc.sess, ActionSwitchSession); err != nil {
		return LoginResult{}, err
	}

	old := sc.sess

	sess := *old
	sess.Context = maps.Clone(old.Context)

	if sess.Context == nil {
		sess.Context = make(map[string]any)
	}

	recreate := false

	// A step that applied the selection is resolved by it.
	var resolved []string

	for _, step := range a.steps {
		sw, ok := step.(Switcher)
		if !ok {
			continue
		}

		mode, err := sw.Switch(ctx, &sess, in.Selection)
		if err != nil {
			return LoginResult{}, NewOAuthErrorFrom(err)
		}

		if mode == SwitchSkip {
			continue
		}

		recreate = recreate || mode == SwitchRecreate

		resolved = append(resolved, step.Name())
	}

	if len(resolved) == 0 {
		return LoginResult{}, NewOAuthErrorFrom(ErrInvalidSelection)
	}

	var info UserInfo

	if err := a.evaluateLoginGates(ctx, &sess, &info, resolved); err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	sess.LastSeen = time.Now()

	// A switch still waiting is replaced; its step tokens are retired once the new one is stored.
	var replaced []string
	if waiting, err := a.pending.Get(ctx, old.ID); err == nil && waiting.Switched != nil {
		replaced = waiting.TokenIDs
	}

	// A switch waiting on a step takes effect once it is resolved; the session stays as it is.
	if sess.Status != session.StatusActive {
		st := pendingState{
			Initialized: true,
			TargetACR:   sess.ACR,
			Resolved:    resolved,
			Recreate:    recreate,
			SwitchedBy:  sc.claims.TokenID,
		}

		prompt, err := a.promptPending(ctx, &sess, &info, sc.client, &st)
		if err != nil {
			return LoginResult{}, err
		}

		st.Switched = sess.Context
		st.SwitchStep = sess.Step

		res, err := a.pendingLoginResult(ctx, &sess, sc.client, st, prompt, "", in.ReturnTo, in.BaseURL, in.MountPath)
		if err != nil {
			return LoginResult{}, err
		}

		for _, id := range replaced {
			_ = a.jti.Revoke(ctx, id)
		}

		return res, nil
	}

	cookie, err := a.applySwitch(ctx, &sess, recreate, append([]string{sc.claims.TokenID}, replaced...), in.IP)
	if err != nil {
		return LoginResult{}, err
	}

	return a.buildLoginResult(ctx, &sess, sc.client, in.ReturnTo, cookie, in.BaseURL, in.MountPath)
}

// commitSession stores sess, creating it when it has no ID yet and revoking the session it
// replaces, retires the credentials in retired and issues its new session cookie, all at once.
func (a *Auth) commitSession(ctx context.Context, sess *session.Session, replaces string, retired []string, now time.Time) (string, string, error) {
	var cookie, jti string

	if err := a.Transaction.Run(ctx, func(ctx context.Context) error {
		if sess.ID == "" {
			if err := a.sessions.Create(ctx, sess); err != nil {
				return err
			}
		} else if err := a.sessions.Update(ctx, sess); err != nil {
			return err
		}

		if replaces != "" {
			if err := a.sessions.Revoke(ctx, replaces); err != nil && !errors.Is(err, session.ErrNotFound) {
				return err
			}
		}

		for _, id := range retired {
			if err := a.jti.Revoke(ctx, id); err != nil {
				return err
			}
		}

		var err error

		cookie, jti, err = a.issueSessionCookie(ctx, sess, now, sess.ExpiresAt)

		return err
	}); err != nil {
		return "", "", NewOAuthErrorFrom(err)
	}

	return cookie, jti, nil
}

// applySwitch stores the switched sess in place of the stored session, recreating it under a
// new ID when asked, retires the credentials in retired and returns the new session cookie.
func (a *Auth) applySwitch(ctx context.Context, sess *session.Session, recreate bool, retired []string, ip string) (string, error) {
	stored := sess.ID

	var replaces string

	if recreate {
		sess.ID = ""
		replaces = stored
	}

	cookie, _, err := a.commitSession(ctx, sess, replaces, retired, time.Now())
	if err != nil {
		return "", err
	}

	_ = deleteSynced(ctx, a.pending, stored)

	if recreate {
		// The IdP session still backs the new session.
		if idt, err := a.fedIDTokens.Get(ctx, stored); err == nil && idt != "" {
			_ = setSynced(ctx, a.fedIDTokens, sess.ID, idt, cache.TTL[string](time.Until(sess.ExpiresAt)))
		}

		_ = deleteSynced(ctx, a.fedIDTokens, stored)
	}

	a.emit(ctx, event.Event{Type: event.TypeSessionSwitched, UserID: sess.UserID, ClientID: sess.ClientID, IP: ip, Detail: map[string]any{"recreated": recreate}})

	return cookie, nil
}
