package auth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/event"
	"azugo.io/auth/mfa"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/core/cache"
	"azugo.io/core/http"
)

// MFAStepRequest carries a step-token call against a pending MFA session.
type MFAStepRequest struct {
	// Token is the step token (or the pending session cookie).
	Token string
	// Method selects the MFA method; empty = the currently selected one.
	Method string
	// Response is the method-specific verification payload, e.g. {"code":"123456"}.
	Response  map[string]any
	ReturnTo  string
	BaseURL   string
	MountPath string
	IP        string
}

// MFAEnrollRequest carries an enrollment call for an active or pending_mfa_setup session.
type MFAEnrollRequest struct {
	Token  string
	Method string
	// Label names the device or app being enrolled.
	Label string
	// Response is the method-specific enrollment payload, e.g. {"code":"123456"}.
	Response  map[string]any
	ReturnTo  string
	BaseURL   string
	MountPath string
	IP        string
}

// MFAEnrollResult is returned by FinishMFAEnroll.
type MFAEnrollResult struct {
	EnrollmentID string
	// Login is set when the enrollment completed a pending_mfa_setup session.
	Login *LoginResult
}

// MFAEnrollmentInfo describes one of the caller's enrollments.
type MFAEnrollmentInfo struct {
	ID         string     `json:"id"`
	Label      string     `json:"label,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// MFAMethodInfo describes one MFA method offered to the caller.
type MFAMethodInfo struct {
	Method      string `json:"method"`
	Enrolled    bool   `json:"enrolled"`
	Interaction string `json:"interaction"`
	// Exclusive methods hold one enrollment per user.
	Exclusive bool `json:"exclusive,omitempty"`
	// Backup methods only back up another factor and cannot be enrolled first.
	Backup bool `json:"backup,omitempty"`
	// Enrollments is listed for active sessions only.
	Enrollments []MFAEnrollmentInfo `json:"enrollments,omitempty"`
}

// stepResult starts the response for a still-pending session: the presented token stays valid
// and a redirect-mode client is sent back to its step page.
func stepResult(sc *stepContext, in MFAStepRequest) LoginResult {
	res := LoginResult{Status: sc.sess.Status}

	// The HttpOnly pending cookie is never handed to page scripts.
	if sc.claims.Type == token.TypeStepToken {
		res.StepToken = in.Token
	}

	if sc.client.ResponseMode == client.ResponseModeRedirect {
		res.ReturnTo = stepRedirect(sc.client, in.ReturnTo)
	}

	return res
}

// pendingMFAResult builds the pending response for the current challenge without opening a new
// one.
func (a *Auth) pendingMFAResult(ctx context.Context, sc *stepContext, in MFAStepRequest) (LoginResult, error) {
	res := stepResult(sc, in)

	if err := a.selectMFA(ctx, sc.sess, sc.client, &sc.state, &res, "", false); err != nil {
		return LoginResult{}, err
	}

	return res, nil
}

// saveStepState persists the (possibly changed) step state of sc.
func (a *Auth) saveStepState(ctx context.Context, sc *stepContext) error {
	if err := setSynced(ctx, a.pending, sc.sess.ID, sc.state, cache.TTL[pendingState](time.Until(sc.sess.ExpiresAt))); err != nil {
		return NewOAuthErrorFrom(err)
	}

	return nil
}

// BeginMFA selects (or switches to) an MFA method for a pending_mfa session, opening its
// challenge, and returns the updated prompt.
func (a *Auth) BeginMFA(ctx context.Context, in MFAStepRequest) (LoginResult, error) {
	sc, err := a.stepSession(ctx, in.Token, session.StatusPendingMFA)
	if err != nil {
		return LoginResult{}, err
	}

	res := stepResult(sc, in)

	if err := a.selectMFA(ctx, sc.sess, sc.client, &sc.state, &res, in.Method, false); err != nil {
		return LoginResult{}, err
	}

	if err := a.saveStepState(ctx, sc); err != nil {
		return LoginResult{}, err
	}

	return res, nil
}

// VerifyMFA evaluates the response for the selected method: approval advances the session,
// denial counts as a throttled failed attempt, pending keeps the challenge open.
func (a *Auth) VerifyMFA(ctx context.Context, in MFAStepRequest) (LoginResult, error) {
	sc, err := a.stepSession(ctx, in.Token, session.StatusPendingMFA)
	if err != nil {
		return LoginResult{}, err
	}

	keys := throttleKeys("mfa:"+sc.sess.UserID, in.IP)

	if err := a.checkThrottle(ctx, keys, sc.client.ID, in.IP); err != nil {
		return LoginResult{}, err
	}

	if sc.state.Method == "" {
		return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "no mfa method selected")
	}

	if in.Method != "" && in.Method != sc.state.Method {
		return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "mfa method is not the selected one")
	}

	m, err := a.mfaMethods.Get(ctx, sc.state.Method)
	if err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	v, err := m.Verify(ctx, sc.sess.UserID, sc.state.ChallengeID, in.Response)
	if err != nil {
		a.refundThrottle(ctx, keys)

		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	return a.settleMFA(ctx, sc, m, v, keys, in)
}

// settleMFA applies a verification outcome to the pending session.
func (a *Auth) settleMFA(ctx context.Context, sc *stepContext, m mfa.Method, v mfa.Verification, keys []string, in MFAStepRequest) (LoginResult, error) {
	detail := map[string]any{"method": sc.state.Method}
	if v.EnrollmentID != "" {
		detail["enrollment_id"] = v.EnrollmentID
	}

	switch v.Result {
	case mfa.VerifyPending:
		a.refundThrottle(ctx, keys)

		return a.pendingMFAResult(ctx, sc, in)
	case mfa.VerifyDenied:
		a.failThrottle(ctx, keys)
		a.emit(ctx, event.Event{Type: event.TypeMFAFailure, UserID: sc.sess.UserID, ClientID: sc.client.ID, IP: in.IP, Detail: detail})

		return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "mfa verification failed")
	case mfa.VerifyApproved:
	default:
		return LoginResult{}, NewOAuthError(http.StatusInternalServerError, ErrCodeServerError, "unexpected mfa verification result")
	}

	if v.EnrollmentID != "" {
		if err := a.mfaStore.Touch(ctx, sc.sess.UserID, v.EnrollmentID, time.Now()); err != nil && !errors.Is(err, mfa.ErrNotEnrolled) {
			return LoginResult{}, NewOAuthErrorFrom(err)
		}
	}

	a.passThrottle(ctx, keys)
	a.resetThrottle(ctx, []string{"mfa-open:" + sc.sess.UserID})
	a.emit(ctx, event.Event{Type: event.TypeMFASuccess, UserID: sc.sess.UserID, ClientID: sc.client.ID, IP: in.IP, Detail: detail})

	sc.sess.MFAMethod = sc.state.Method
	sc.sess.MFAEnrollmentID = v.EnrollmentID
	sc.sess.AMR = mergeAMR(sc.sess.AMR, mfa.MethodAMR(m))

	return a.advanceSession(ctx, sc, in.ReturnTo, in.BaseURL, in.MountPath)
}

// ResendMFA re-opens the selected challenge (a fresh code) under the resend cooldown and cap.
func (a *Auth) ResendMFA(ctx context.Context, in MFAStepRequest) (LoginResult, error) {
	sc, err := a.stepSession(ctx, in.Token, session.StatusPendingMFA)
	if err != nil {
		return LoginResult{}, err
	}

	if sc.state.ChallengeID == "" {
		return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "selected mfa method has nothing to resend")
	}

	if in.Method != "" && in.Method != sc.state.Method {
		return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "mfa method is not the selected one")
	}

	res := stepResult(sc, in)

	if err := a.selectMFA(ctx, sc.sess, sc.client, &sc.state, &res, "", true); err != nil {
		return LoginResult{}, err
	}

	if err := a.saveStepState(ctx, sc); err != nil {
		return LoginResult{}, err
	}

	return res, nil
}

// MFAStatus polls the selected method: an async factor that has been approved out-of-band
// advances the session; otherwise the pending prompt is returned. Never throttled.
func (a *Auth) MFAStatus(ctx context.Context, in MFAStepRequest) (LoginResult, error) {
	sc, err := a.stepSession(ctx, in.Token, session.StatusPendingMFA)
	if err != nil {
		return LoginResult{}, err
	}

	if sc.state.Method == "" {
		return a.pendingMFAResult(ctx, sc, in)
	}

	m, err := a.mfaMethods.Get(ctx, sc.state.Method)
	if err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	if mfa.MethodInteraction(m) != mfa.InteractionPoll {
		return a.pendingMFAResult(ctx, sc, in)
	}

	v, err := m.Verify(ctx, sc.sess.UserID, sc.state.ChallengeID, nil)
	if err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	// A poll is never a failed attempt: only the approval path touches the throttle.
	return a.settleMFA(ctx, sc, m, v, nil, in)
}

// ListMFAMethods returns the MFA methods the caller's client permits, flagged by enrollment.
// It accepts an active session token or a pending step token.
func (a *Auth) ListMFAMethods(ctx context.Context, tok string) ([]MFAMethodInfo, error) {
	if a.mfaStore == nil {
		return nil, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "mfa is not enabled")
	}

	sc, err := a.stepSession(ctx, tok, session.StatusActive, session.StatusPendingMFA, session.StatusPendingMFASetup)
	if err != nil {
		return nil, err
	}

	permitted, _, err := a.mfaMethodSets(ctx, sc.sess.UserID, sc.client, a.acrLevel(sc.state.TargetACR))
	if err != nil {
		return nil, NewOAuthErrorFrom(err)
	}

	enrollments, err := a.mfaStore.List(ctx, sc.sess.UserID)
	if err != nil {
		return nil, NewOAuthErrorFrom(err)
	}

	out := make([]MFAMethodInfo, 0, len(permitted))

	for _, name := range permitted {
		m, err := a.mfaMethods.Get(ctx, name)
		if err != nil {
			return nil, NewOAuthErrorFrom(err)
		}

		info := MFAMethodInfo{Method: name, Interaction: mfa.MethodInteraction(m), Exclusive: mfa.MethodExclusive(m), Backup: mfa.MethodBackup(m)}

		for _, e := range enrollments {
			if e.Method != name {
				continue
			}

			info.Enrolled = true

			// A password-only caller learns nothing about the devices it has to get past.
			if sc.sess.Status == session.StatusActive {
				info.Enrollments = append(info.Enrollments, MFAEnrollmentInfo{ID: e.ID, Label: e.Label, CreatedAt: e.CreatedAt, LastUsedAt: e.LastUsedAt})
			}
		}

		out = append(out, info)
	}

	return out, nil
}

// mfaVerified reports whether sess passed a second factor, locally or through an amr value its
// satisfied level accepts in place of one.
func (a *Auth) mfaVerified(sess *session.Session) bool {
	if sess.MFAMethod != "" {
		return true
	}

	lvl := a.acrLevel(sess.ACR)

	return lvl != nil && intersects(sess.AMR, lvl.MFASatisfiedByAMR)
}

// enrollSession resolves an enrollment token to an active or pending_mfa_setup session and
// checks method is permitted and known.
func (a *Auth) enrollSession(ctx context.Context, tok, method string) (*stepContext, mfa.Method, error) {
	if a.mfaStore == nil {
		return nil, nil, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "mfa is not enabled")
	}

	sc, err := a.stepSession(ctx, tok, session.StatusActive, session.StatusPendingMFASetup)
	if err != nil {
		return nil, nil, err
	}

	enrolled, err := mfa.EnrolledMethods(ctx, a.mfaStore, sc.sess.UserID)
	if err != nil {
		return nil, nil, NewOAuthErrorFrom(err)
	}

	if len(enrolled) > 0 && !a.mfaVerified(sc.sess) {
		return nil, nil, NewOAuthErrorFrom(ErrUnmetAuthenticationRequirements)
	}

	permitted, _, err := a.mfaMethodSets(ctx, sc.sess.UserID, sc.client, a.acrLevel(sc.state.TargetACR))
	if err != nil {
		return nil, nil, NewOAuthErrorFrom(err)
	}

	if !slices.Contains(permitted, method) {
		return nil, nil, NewOAuthErrorFrom(mfa.ErrUnknownMethod)
	}

	m, err := a.mfaMethods.Get(ctx, method)
	if err != nil {
		return nil, nil, NewOAuthErrorFrom(err)
	}

	return sc, m, nil
}

func enrollmentKey(userID, method string) string {
	return userID + "|" + method
}

// BeginMFAEnroll starts enrolling the caller in method and returns the data the client needs
// (TOTP secret and otpauth URI, recovery codes, ...). A second enrollment in an exclusive
// method is refused; revoke it first.
func (a *Auth) BeginMFAEnroll(ctx context.Context, in MFAEnrollRequest) (map[string]any, error) {
	sc, m, err := a.enrollSession(ctx, in.Token, in.Method)
	if err != nil {
		return nil, err
	}

	if mfa.MethodBackup(m) {
		enrolled, err := mfa.EnrolledMethods(ctx, a.mfaStore, sc.sess.UserID)
		if err != nil {
			return nil, NewOAuthErrorFrom(err)
		}

		primary, err := a.primaryMethods(ctx, enrolled)
		if err != nil {
			return nil, NewOAuthErrorFrom(err)
		}

		if len(primary) == 0 {
			return nil, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "a backup method requires another mfa method")
		}
	}

	if mfa.MethodExclusive(m) {
		enrolled, err := mfa.Enrolled(ctx, a.mfaStore, sc.sess.UserID, in.Method)
		if err != nil {
			return nil, NewOAuthErrorFrom(err)
		}

		if len(enrolled) > 0 {
			return nil, NewOAuthError(http.StatusConflict, ErrCodeInvalidRequest, "mfa method already enrolled")
		}
	}

	info, err := a.users.GetUser(ctx, sc.sess.UserID)
	if err != nil {
		return nil, NewOAuthErrorFrom(err)
	}

	keys := []string{"mfa-enroll:" + sc.sess.UserID}

	if err := a.checkThrottle(ctx, keys, sc.client.ID, in.IP); err != nil {
		return nil, err
	}

	data, err := m.BeginEnroll(ctx, sc.sess.UserID, info)
	if err != nil {
		a.refundThrottle(ctx, keys)

		return nil, NewOAuthErrorFrom(err)
	}

	a.failThrottle(ctx, keys)

	if err := setSynced(ctx, a.enrollments, enrollmentKey(sc.sess.UserID, in.Method), mfaEnrollment{State: data.State}, cache.TTL[mfaEnrollment](a.config.AccessTokenTTL)); err != nil {
		return nil, NewOAuthErrorFrom(err)
	}

	return data.Data, nil
}

// FinishMFAEnroll verifies the enrollment response and persists the factor. Completing a
// pending_mfa_setup session counts as a passed factor and advances it.
func (a *Auth) FinishMFAEnroll(ctx context.Context, in MFAEnrollRequest) (MFAEnrollResult, error) {
	sc, m, err := a.enrollSession(ctx, in.Token, in.Method)
	if err != nil {
		return MFAEnrollResult{}, err
	}

	keys := throttleKeys("mfa:"+sc.sess.UserID, in.IP)

	if err := a.checkThrottle(ctx, keys, sc.client.ID, in.IP); err != nil {
		return MFAEnrollResult{}, err
	}

	key := enrollmentKey(sc.sess.UserID, in.Method)

	pending, err := a.enrollments.Get(ctx, key)
	if err != nil {
		a.refundThrottle(ctx, keys)

		var knf cache.KeyNotFoundError
		if errors.As(err, &knf) {
			return MFAEnrollResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "no mfa enrollment in progress")
		}

		return MFAEnrollResult{}, NewOAuthErrorFrom(err)
	}

	detail := map[string]any{"method": in.Method}

	secret, err := m.FinishEnroll(ctx, sc.sess.UserID, pending.State, in.Response)
	if err != nil {
		if errors.Is(err, mfa.ErrInvalidResponse) {
			a.failThrottle(ctx, keys)
			a.emit(ctx, event.Event{Type: event.TypeMFAFailure, UserID: sc.sess.UserID, ClientID: sc.client.ID, IP: in.IP, Detail: detail})
		} else {
			a.refundThrottle(ctx, keys)
		}

		return MFAEnrollResult{}, NewOAuthErrorFrom(err)
	}

	a.passThrottle(ctx, keys)

	id, err := newJTI()
	if err != nil {
		return MFAEnrollResult{}, NewOAuthErrorFrom(err)
	}

	// Request strings may alias a transport buffer; the enrollment outlives the request.
	if err := a.mfaStore.Enroll(ctx, &mfa.Enrollment{
		ID:        id,
		UserID:    sc.sess.UserID,
		Method:    strings.Clone(in.Method),
		Label:     strings.Clone(in.Label),
		Secret:    secret,
		CreatedAt: time.Now(),
	}); err != nil {
		return MFAEnrollResult{}, NewOAuthErrorFrom(err)
	}

	detail["enrollment_id"] = id

	_ = deleteSynced(ctx, a.enrollments, key)
	a.emit(ctx, event.Event{Type: event.TypeMFAEnrolled, UserID: sc.sess.UserID, ClientID: sc.client.ID, IP: in.IP, Detail: detail})

	// The session proved it holds the new factor, which counts as passing one; a backup
	// method proves nothing.
	if !a.mfaVerified(sc.sess) && !mfa.MethodBackup(m) {
		sc.sess.MFAMethod = in.Method
		sc.sess.MFAEnrollmentID = id
		sc.sess.AMR = mergeAMR(sc.sess.AMR, mfa.MethodAMR(m))
	}

	if sc.sess.Status != session.StatusPendingMFASetup {
		sc.sess.ACR = a.satisfiedACR(sc.sess)

		if err := a.sessions.Update(ctx, sc.sess); err != nil {
			return MFAEnrollResult{}, NewOAuthErrorFrom(err)
		}

		return MFAEnrollResult{EnrollmentID: id}, nil
	}

	login, err := a.advanceSession(ctx, sc, in.ReturnTo, in.BaseURL, in.MountPath)
	if err != nil {
		return MFAEnrollResult{}, err
	}

	return MFAEnrollResult{EnrollmentID: id, Login: &login}, nil
}

// revokeSession resolves tok to a session that passed a second factor, so a stolen password
// alone cannot strip the account's factors.
func (a *Auth) revokeSession(ctx context.Context, tok string) (UserInfo, *session.Session, error) {
	if a.mfaStore == nil {
		return UserInfo{}, nil, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "mfa is not enabled")
	}

	info, sess, err := a.IntrospectFirstParty(ctx, tok)
	if err != nil {
		return UserInfo{}, nil, err
	}

	if !a.mfaVerified(sess) {
		return UserInfo{}, nil, NewOAuthErrorFrom(ErrUnmetAuthenticationRequirements)
	}

	return info, sess, nil
}

// RevokeMFA removes every enrollment of the caller in method.
func (a *Auth) RevokeMFA(ctx context.Context, tok, method string) error {
	info, sess, err := a.revokeSession(ctx, tok)
	if err != nil {
		return err
	}

	if _, err := a.mfaMethods.Get(ctx, method); err != nil {
		return NewOAuthErrorFrom(err)
	}

	enrolled, err := mfa.Enrolled(ctx, a.mfaStore, info.ID, method)
	if err != nil {
		return NewOAuthErrorFrom(err)
	}

	if len(enrolled) == 0 {
		return NewOAuthErrorFrom(mfa.ErrNotEnrolled)
	}

	for _, e := range enrolled {
		if err := a.mfaStore.Revoke(ctx, info.ID, e.ID); err != nil && !errors.Is(err, mfa.ErrNotEnrolled) {
			return NewOAuthErrorFrom(err)
		}

		a.emit(ctx, event.Event{Type: event.TypeMFARevoked, UserID: info.ID, ClientID: sess.ClientID, Detail: map[string]any{"method": method, "enrollment_id": e.ID}})
	}

	return nil
}

// RevokeMFAEnrollment removes one enrollment of the caller in method.
func (a *Auth) RevokeMFAEnrollment(ctx context.Context, tok, method, id string) error {
	info, sess, err := a.revokeSession(ctx, tok)
	if err != nil {
		return err
	}

	enrolled, err := mfa.Enrolled(ctx, a.mfaStore, info.ID, method)
	if err != nil {
		return NewOAuthErrorFrom(err)
	}

	if !slices.ContainsFunc(enrolled, func(e *mfa.Enrollment) bool { return e.ID == id }) {
		return NewOAuthErrorFrom(mfa.ErrNotEnrolled)
	}

	if err := a.mfaStore.Revoke(ctx, info.ID, id); err != nil {
		return NewOAuthErrorFrom(err)
	}

	a.emit(ctx, event.Event{Type: event.TypeMFARevoked, UserID: info.ID, ClientID: sess.ClientID, Detail: map[string]any{"method": method, "enrollment_id": id}})

	return nil
}

// EnrolledMFA returns the MFA methods userID is enrolled in, or nil when MFA is disabled.
func (a *Auth) EnrolledMFA(ctx context.Context, userID string) ([]string, error) {
	if a.mfaStore == nil {
		return nil, nil
	}

	return mfa.EnrolledMethods(ctx, a.mfaStore, userID)
}
