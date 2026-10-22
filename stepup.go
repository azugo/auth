package auth

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/event"
	"azugo.io/auth/mfa"
	"azugo.io/auth/session"

	"azugo.io/core/cache"
	"azugo.io/core/http"
)

// Sensitive account actions the library asks a StepUpPolicy about.
// ActionEnrollMFA and ActionRevokeMFA default to a second factor within the last 5 minutes when
// the account had a factor before the session; enrolling a first factor defaults to any
// authentication within the last 5 minutes.
const (
	ActionAddContact     = "contact.add"
	ActionRemoveContact  = "contact.remove"
	ActionPrimaryContact = "contact.primary"
	ActionChangePassword = "password.change"
	ActionEnrollMFA      = "mfa.enroll"
	ActionRevokeMFA      = "mfa.revoke"
	ActionUnlinkIdentity = "identity.unlink"
	ActionRevokeSession  = "session.revoke"
	ActionUpdateProfile  = "profile.update"
	ActionSwitchSession  = "session.switch"
)

// reauthPassword is the re-authentication method name of the password.
const reauthPassword = "password"

// StepUpRequirement is the authentication a sensitive action requires.
type StepUpRequirement struct {
	// MaxAge is how long ago the session may last have authenticated; 0 = no limit.
	MaxAge time.Duration
	// ACR is the minimum authentication context class; "" = any.
	ACR string
	// Methods are the amr values the last authentication must have used, e.g. ["otp"]; empty =
	// any.
	Methods []string
	// MFA requires the last authentication to have passed a second factor.
	MFA bool
}

// NoStepUp lets any active session perform an action, overriding a library default.
var NoStepUp = StepUpRequirement{}

// StepUpPolicy decides the authentication a session needs for a sensitive account action.
type StepUpPolicy interface {
	// Required returns the authentication sess must have for action; ok false leaves the library
	// default for action, if any, and NoStepUp with ok true requires nothing.
	Required(ctx context.Context, sess *session.Session, action string) (req StepUpRequirement, ok bool)
}

// StepUpPolicyFunc adapts a plain function to the StepUpPolicy interface.
type StepUpPolicyFunc func(ctx context.Context, sess *session.Session, action string) (StepUpRequirement, bool)

// Required implements StepUpPolicy.
func (f StepUpPolicyFunc) Required(ctx context.Context, sess *session.Session, action string) (StepUpRequirement, bool) {
	return f(ctx, sess, action)
}

// StepUp requires the authentication policy decides before sensitive account actions.
func StepUp(policy StepUpPolicy) Option {
	return func(a *Auth) { a.stepUp = policy }
}

// ReauthRequest starts re-authenticating the active session behind Token.
type ReauthRequest struct {
	Token string
	// Action is the sensitive action to re-authenticate for; it selects the acceptable methods.
	Action string
	// Method is the method to use; empty = the first acceptable one.
	Method string
	IP     string
}

// ReauthResult describes a re-authentication in progress, like a pending MFA prompt.
type ReauthResult struct {
	Available   []string
	Selected    string
	Interaction string
	Data        map[string]any
	// Password asks for the password together with the selected factor's proof.
	Password bool
}

// ReauthVerifyRequest carries the proof for the re-authentication in progress.
type ReauthVerifyRequest struct {
	Token string
	// Password is the proof of the password method.
	Password string
	// Response is the proof of an MFA method, e.g. {"code":"123456"}; nil polls an asynchronous
	// one.
	Response map[string]any
	IP       string
}

// reauthState is the re-authentication in progress of a session, cached under its ID.
type reauthState struct {
	Action        string
	Method        string
	ChallengeID   string
	ChallengeData map[string]any
	// WithPassword requires the password together with the factor.
	WithPassword   bool
	PasswordProven bool
}

// StepUpPolicy returns the configured step-up policy, or nil when none is set.
func (a *Auth) StepUpPolicy() StepUpPolicy {
	return a.stepUp
}

// StepUpEnabled reports whether any action may require step-up: a policy is configured, or MFA or
// contact management is enabled and its library defaults apply.
func (a *Auth) StepUpEnabled() bool {
	_, contacts := a.users.(ContactManager)

	return a.stepUp != nil || a.mfaStore != nil || len(a.contacts) > 0 || contacts
}

// defaultStepUpActions are the actions the library guards when the policy leaves them.
var defaultStepUpActions = []string{ActionEnrollMFA, ActionRevokeMFA, ActionAddContact, ActionRemoveContact, ActionPrimaryContact}

// stepUpNeeded resolves what action needs from sess, the app's policy else the library default
// judged on the account's enrollments, and reports whether sessions latest authentication falls
// short of it.
func (a *Auth) stepUpNeeded(ctx context.Context, sess *session.Session, action string, enrollments []*mfa.Enrollment) (StepUpRequirement, bool) {
	var (
		req StepUpRequirement
		ok  bool
	)

	if a.stepUp != nil {
		req, ok = a.stepUp.Required(ctx, sess, action)
	}

	if !ok && slices.Contains(defaultStepUpActions, action) {
		switch {
		// Changing the factors or contacts of an account that had a factor before this session
		// needs a fresh second factor.
		case slices.ContainsFunc(enrollments, func(e *mfa.Enrollment) bool { return e.CreatedAt.Before(sess.CreatedAt) }):
			req = StepUpRequirement{MFA: true, MaxAge: 5 * time.Minute}
			ok = true
		// Only factors enrolled through this session are left to revoke.
		case action != ActionRevokeMFA:
			req = StepUpRequirement{MaxAge: 5 * time.Minute}
			ok = true
		}
	}

	if !ok {
		return req, false
	}

	met := (req.MaxAge <= 0 || time.Since(sess.AuthenticatedAt()) <= req.MaxAge) &&
		(len(req.Methods) == 0 || intersects(sess.AuthenticatedMethods(), req.Methods)) &&
		(!req.MFA || sess.AuthenticatedMFA()) &&
		a.ACRSatisfies(sess.AuthenticatedACR(), req.ACR)

	return req, !met
}

// RequireStepUp resolves the active first-party session behind token and checks it against the
// step-up policy for action.
func (a *Auth) RequireStepUp(ctx context.Context, tok, action string) (UserInfo, error) {
	info, sess, err := a.IntrospectFirstParty(ctx, tok)
	if err != nil {
		return UserInfo{}, err
	}

	if err := a.checkStepUp(ctx, sess, action); err != nil {
		return UserInfo{}, err
	}

	return info, nil
}

// checkStepUp refuses action unless sess meets what the policy requires for it.
func (a *Auth) checkStepUp(ctx context.Context, sess *session.Session, action string) error {
	var enrollments []*mfa.Enrollment

	if a.mfaStore != nil && slices.Contains(defaultStepUpActions, action) {
		var err error

		if enrollments, err = a.mfaStore.List(ctx, sess.UserID); err != nil {
			return NewOAuthErrorFrom(err)
		}
	}

	req, needed := a.stepUpNeeded(ctx, sess, action, enrollments)
	if !needed {
		return nil
	}

	return &OAuthError{
		Code:        ErrCodeInsufficientUserAuthentication,
		Description: "re-authentication required",
		status:      http.StatusUnauthorized,
		acrValues:   req.ACR,
		maxAge:      int(req.MaxAge.Seconds()),
	}
}

// authACR returns the level an authentication proving primary (empty when it proved none), with
// amr and mfaMethod, reaches on its own.
func (a *Auth) authACR(primary string, amr []string, mfaMethod string) string {
	if best := a.highestLevel(primary, amr, mfaMethod); best != nil {
		return best.Value
	}

	return ""
}

// reauthMethods returns the methods that can re-authenticate sc for req: the password, and MFA
// factors among enrollments enrolled before the session was created, the second list naming
// the factors that reach req's level only together with the password.
func (a *Auth) reauthMethods(ctx context.Context, sc *stepContext, req StepUpRequirement, enrollments []*mfa.Enrollment) ([]string, []string, error) {
	var out, withPassword []string

	_, passwords := a.users.(PasswordAuthenticator)

	// The password is offered alone only when it reaches the required level on its own.
	if passwords && !req.MFA && (len(req.Methods) == 0 || slices.Contains(req.Methods, amrPassword)) && a.ACRSatisfies(a.authACR(client.AuthMethodPassword, []string{amrPassword}, ""), req.ACR) {
		out = append(out, reauthPassword)
	}

	if a.mfaStore == nil {
		return out, nil, nil
	}

	names, err := a.mfaMethods.Names(ctx)
	if err != nil {
		return nil, nil, err
	}

	permitted := filterMethods(names, sc.client, a.acrLevel(req.ACR))

	for _, e := range enrollments {
		name := e.Method

		// A factor enrolled through this session proves nothing about who holds it, and a method
		// configured under the password's name could not be told apart from it.
		if !e.CreatedAt.Before(sc.sess.CreatedAt) || name == reauthPassword || slices.Contains(out, name) || !slices.Contains(permitted, name) {
			continue
		}

		m, err := a.mfaMethods.Get(ctx, name)
		if err != nil {
			return nil, nil, err
		}

		amr := mfa.MethodAMR(m)
		if len(req.Methods) > 0 && !intersects(amr, req.Methods) {
			continue
		}

		mfaMethod := name
		if mfa.MethodBackup(m) {
			mfaMethod = ""
		}

		switch {
		case a.ACRSatisfies(a.authACR("", amr, mfaMethod), req.ACR):
			out = append(out, name)
		case passwords && a.ACRSatisfies(a.authACR(client.AuthMethodPassword, mergeAMR([]string{amrPassword}, amr), mfaMethod), req.ACR):
			out = append(out, name)
			withPassword = append(withPassword, name)
		}
	}

	return out, withPassword, nil
}

// BeginReauth starts re-authenticating an active session for action, opening the challenge of
// the selected MFA method.
func (a *Auth) BeginReauth(ctx context.Context, in ReauthRequest) (ReauthResult, error) {
	if !a.StepUpEnabled() {
		return ReauthResult{}, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "re-authentication is not enabled")
	}

	sc, err := a.stepSession(ctx, in.Token, session.StatusActive)
	if err != nil {
		return ReauthResult{}, err
	}

	// The requirement and the methods judge one listing of the account's enrollments.
	var enrollments []*mfa.Enrollment

	if a.mfaStore != nil {
		if enrollments, err = a.mfaStore.List(ctx, sc.sess.UserID); err != nil {
			return ReauthResult{}, NewOAuthErrorFrom(err)
		}
	}

	// A needless re-authentication would only replace a stronger one.
	req, needed := a.stepUpNeeded(ctx, sc.sess, in.Action, enrollments)
	if !needed {
		return ReauthResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "re-authentication is not needed")
	}

	available, withPassword, err := a.reauthMethods(ctx, sc, req, enrollments)
	if err != nil {
		return ReauthResult{}, NewOAuthErrorFrom(err)
	}

	if len(available) == 0 {
		return ReauthResult{}, NewOAuthErrorFrom(ErrUnmetAuthenticationRequirements)
	}

	method := cmp.Or(in.Method, available[0])
	if !slices.Contains(available, method) {
		return ReauthResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "re-authentication method is not available")
	}

	st := reauthState{Action: in.Action, Method: method, WithPassword: slices.Contains(withPassword, method)}
	res := ReauthResult{Available: available, Selected: method, Interaction: reauthPassword, Password: st.WithPassword}

	expiresAt := time.Now().Add(a.config.AccessTokenTTL)
	if expiresAt.After(sc.sess.ExpiresAt) {
		expiresAt = sc.sess.ExpiresAt
	}

	if method != reauthPassword {
		m, err := a.mfaMethods.Get(ctx, method)
		if err != nil {
			return ReauthResult{}, NewOAuthErrorFrom(err)
		}

		if st.ChallengeID, st.ChallengeData, err = a.openMFAChallenge(ctx, "reauth:"+sc.sess.ID, sc.sess.UserID, expiresAt, sc.client.ID, method, m); err != nil {
			return ReauthResult{}, err
		}

		res.Interaction = mfa.MethodInteraction(m)
		res.Data = st.ChallengeData
	}

	if err := setSynced(ctx, a.reauths, sc.sess.ID, st, cache.TTL[reauthState](time.Until(expiresAt))); err != nil {
		return ReauthResult{}, NewOAuthErrorFrom(err)
	}

	return res, nil
}

// VerifyReauth checks the proof of the re-authentication in progress and, once approved,
// refreshes the session's AuthTime and AuthMethods and recomputes its ACR.
func (a *Auth) VerifyReauth(ctx context.Context, in ReauthVerifyRequest) error {
	if !a.StepUpEnabled() {
		return NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "re-authentication is not enabled")
	}

	sc, err := a.stepSession(ctx, in.Token, session.StatusActive)
	if err != nil {
		return err
	}

	st, err := a.reauths.Get(ctx, sc.sess.ID)
	if err != nil {
		if _, ok := errors.AsType[cache.KeyNotFoundError](err); !ok {
			return NewOAuthErrorFrom(err)
		}
	}

	if st.Method == "" {
		return NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "no re-authentication in progress")
	}

	sess := sc.sess
	detail := map[string]any{"method": st.Method, "action": st.Action}

	var amr []string

	mfaMethod := ""

	// The password goes first, alone or ahead of a factor that needs it to reach the level.
	if st.Method == reauthPassword || st.WithPassword && !st.PasswordProven {
		verifier, _ := a.users.(PasswordAuthenticator)
		identity := "pwdchange:" + sess.UserID
		keys := throttleKeys(identity, in.IP)

		if err := a.checkThrottle(ctx, keys, sc.client.ID, in.IP); err != nil {
			return err
		}

		if err := verifier.VerifyPassword(ctx, sess.UserID, in.Password); err != nil {
			if errors.Is(err, ErrInvalidCredentials) {
				a.failThrottle(ctx, keys)
			} else {
				a.refundThrottle(ctx, keys)
			}

			return NewOAuthErrorFrom(err)
		}

		a.passThrottle(ctx, keys, identity)

		if st.WithPassword {
			st.PasswordProven = true

			// The state keeps its remaining lifetime; a cache that cannot tell it gets a fresh one.
			ttl, ok, err := a.reauths.TTL(ctx, sess.ID)
			if err != nil || !ok || ttl <= 0 {
				ttl = min(a.config.AccessTokenTTL, time.Until(sess.ExpiresAt))
			}

			if err := setSynced(ctx, a.reauths, sess.ID, st, cache.TTL[reauthState](ttl)); err != nil {
				return NewOAuthErrorFrom(err)
			}
		}
	}

	if st.Method == reauthPassword || st.WithPassword {
		amr = []string{amrPassword}
	}

	if st.Method != reauthPassword {
		identity := "mfa:" + sess.UserID
		keys := throttleKeys(identity, in.IP)

		if err := a.checkThrottle(ctx, keys, sc.client.ID, in.IP); err != nil {
			return err
		}

		m, err := a.mfaMethods.Get(ctx, st.Method)
		if err != nil {
			a.refundThrottle(ctx, keys)

			return NewOAuthErrorFrom(err)
		}

		v, err := m.Verify(ctx, sess.UserID, st.ChallengeID, in.Response)
		if err != nil {
			a.refundThrottle(ctx, keys)

			return NewOAuthErrorFrom(err)
		}

		// An approval that names no enrollment cannot prove its factor predates the session. That is
		// the method's limit rather than a wrong guess, so it does not count as one.
		if v.Result == mfa.VerifyApproved && v.EnrollmentID == "" {
			a.refundThrottle(ctx, keys)

			return NewOAuthErrorFrom(ErrUnmetAuthenticationRequirements)
		}

		if v.Result == mfa.VerifyApproved {
			enrollments, err := a.mfaStore.List(ctx, sess.UserID)
			if err != nil {
				a.refundThrottle(ctx, keys)

				return NewOAuthErrorFrom(err)
			}

			// The enrollment that answered must predate the session.
			if !slices.ContainsFunc(enrollments, func(e *mfa.Enrollment) bool {
				return e.ID == v.EnrollmentID && e.CreatedAt.Before(sess.CreatedAt)
			}) {
				v.Result = mfa.VerifyDenied
			}
		}

		result, err := a.settleFactor(ctx, sess.UserID, sc.client.ID, in.IP, v, keys, detail)
		if err != nil {
			return err
		}

		if result == mfa.VerifyPending {
			return NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "re-authentication is awaiting approval")
		}

		if result == mfa.VerifyDenied {
			return NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "re-authentication failed")
		}

		if !mfa.MethodBackup(m) {
			mfaMethod = st.Method

			if sess.MFAMethod == "" {
				sess.MFAMethod = st.Method
				sess.MFAEnrollmentID = v.EnrollmentID
			}
		}

		amr = mergeAMR(amr, mfa.MethodAMR(m))
	}

	sess.AuthTime = time.Now()
	sess.AuthMethods = amr
	sess.AuthMFA = st.Method != reauthPassword
	// A re-authentication proves only itself, never the session's original primary method.
	var primary string
	if slices.Contains(amr, amrPassword) {
		primary = client.AuthMethodPassword
	}

	sess.AuthACR = a.authACR(primary, amr, mfaMethod)
	sess.AMR = mergeAMR(sess.AMR, amr)
	sess.ACR = a.satisfiedACR(sess)

	if err := a.sessions.Update(ctx, sess); err != nil {
		return NewOAuthErrorFrom(err)
	}

	_ = deleteSynced(ctx, a.reauths, sess.ID)

	a.emit(ctx, event.Event{Type: event.TypeSessionReauthenticated, UserID: sess.UserID, ClientID: sc.client.ID, IP: in.IP, Detail: detail})

	return nil
}
