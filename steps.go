package auth

import (
	"context"
	"errors"
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
}

// mfaEnrollment is the driver state of an in-progress enrollment.
type mfaEnrollment struct {
	State []byte
}

// stepContext bundles a pending session with what the step endpoints need about it.
type stepContext struct {
	sess   *session.Session
	claims *token.AccessClaims
	client *client.Client
	state  pendingState
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

// evaluateSteps resolves the target ACR and the built-in login steps for session.
func (a *Auth) evaluateSteps(ctx context.Context, sess *session.Session, cl *client.Client, req acrRequest) (pendingState, error) {
	var names, primary, enrolled []string

	if a.mfaStore != nil {
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

	st := pendingState{Initialized: true, Essential: req.Essential}
	if target != nil {
		st.TargetACR = target.Value
	}

	sess.Status = session.StatusActive

	required := cl.MFAPolicy == client.MFAPolicyRequired || (target != nil && target.RequireMFA)
	optional := cl.MFAPolicy == client.MFAPolicyOptional
	satisfied := sess.MFAMethod != "" || (target != nil && intersects(sess.AMR, target.MFASatisfiedByAMR))

	if a.mfaStore != nil && !satisfied && (required || optional) {
		permitted := filterMethods(names, cl, target)

		available := 0

		for _, m := range enrolled {
			if slices.Contains(permitted, m) {
				available++
			}
		}

		// Only a user without any factor is onboarded; an enrolled factor that the client or
		// level does not permit must not be bypassed by enrolling a new one.
		switch {
		case available > 0:
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

	return st, nil
}

// startSession resolves the login steps for a freshly authenticated sess, persists it and
// returns the final credentials when active or a step token when pending.
func (a *Auth) startSession(ctx context.Context, sess *session.Session, cl *client.Client, req acrRequest, returnTo string, baseURL, mountPath string) (LoginResult, error) {
	st, err := a.evaluateSteps(ctx, sess, cl, req)
	if err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	now := time.Now()
	sess.CreatedAt = now
	sess.LastSeen = now
	sess.ExpiresAt = now.Add(a.config.SessionTTL)

	// A pending session lives only as long as its step token.
	if sess.Status != session.StatusActive {
		sess.ExpiresAt = now.Add(a.config.AccessTokenTTL)
	}

	var cookie, jti string

	if err := a.Transaction.Run(ctx, func(ctx context.Context) error {
		if err := a.sessions.Create(ctx, sess); err != nil {
			return err
		}

		var err error

		cookie, jti, err = a.issueSessionCookie(ctx, sess, now, sess.ExpiresAt)

		return err
	}); err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	if sess.Status == session.StatusActive {
		return a.buildLoginResult(ctx, sess, cl, returnTo, cookie, baseURL, mountPath)
	}

	st.TokenIDs = append(st.TokenIDs, jti)

	return a.pendingLoginResult(ctx, sess, cl, st, cookie, returnTo, baseURL, mountPath)
}

// pendingLoginResult persists the step state, opens the first MFA challenge when needed and
// issues the step token for a pending session.
func (a *Auth) pendingLoginResult(ctx context.Context, sess *session.Session, cl *client.Client, st pendingState, cookie, returnTo string, baseURL, mountPath string) (LoginResult, error) {
	res := LoginResult{Status: sess.Status, ACR: sess.ACR, AMR: sess.AMR}

	if cookie != "" {
		res.Cookie = a.cookieDirective(cookie, time.Until(sess.ExpiresAt), baseURL, mountPath)
	}

	if sess.Status == session.StatusPendingMFA {
		if err := a.selectMFA(ctx, sess, cl, &st, &res, "", false); err != nil {
			return LoginResult{}, err
		}
	}

	step, jti, err := a.issueStepToken(ctx, sess, cl)
	if err != nil {
		return LoginResult{}, err
	}

	st.TokenIDs = append(st.TokenIDs, jti)

	if err := setSynced(ctx, a.pending, sess.ID, st, cache.TTL[pendingState](time.Until(sess.ExpiresAt))); err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	res.StepToken = step

	if cl.ResponseMode == client.ResponseModeRedirect {
		res.ReturnTo = stepRedirect(cl, returnTo)
	}

	return res, nil
}

// limitChallenge claims the right to issue another challenge for method. Re-issuing one is a
// resend whichever way it is reached, so it is capped and rate limited per session, and every
// issue is bounded per user across sessions so repeated logins cannot flood a device.
func (a *Auth) limitChallenge(ctx context.Context, sess *session.Session, cl *client.Client, method string) (string, error) {
	issued, err := a.challenges.Get(ctx, sess.ID+":"+method)
	if err != nil {
		return "", NewOAuthErrorFrom(err)
	}

	if issued > int64(a.config.Throttle.MFAMaxResends) {
		return "", NewThrottledError(time.Until(sess.ExpiresAt))
	}

	if err := a.checkThrottle(ctx, []string{"mfa-open:" + sess.UserID}, cl.ID, ""); err != nil {
		return "", err
	}

	cooldown := a.config.Throttle.MFAResendCooldown
	if cooldown <= 0 {
		return "", nil
	}

	// Claiming is atomic and the marker's own lifetime is the cooldown, so its presence is
	// the answer and concurrent callers cannot both pass.
	key := "cooldown:" + sess.ID + ":" + method

	fresh, err := a.challenges.Add(ctx, key, 1, cache.TTL[int64](cooldown))
	if err != nil {
		a.refundThrottle(ctx, []string{"mfa-open:" + sess.UserID})

		return "", NewOAuthErrorFrom(err)
	}

	if !fresh {
		a.refundThrottle(ctx, []string{"mfa-open:" + sess.UserID})

		remaining, _, err := a.challenges.TTL(ctx, key)
		if err != nil {
			return "", NewOAuthErrorFrom(err)
		}

		if remaining <= 0 {
			remaining = cooldown
		}

		return "", NewThrottledError(remaining)
	}

	return key, nil
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
		cooldownKey, err := a.limitChallenge(ctx, sess, cl, method)
		if err != nil {
			return err
		}

		challengeID, data, err := m.BeginVerify(ctx, sess.UserID)

		// A self-contained method issues nothing and a failed one delivered nothing, so
		// neither counts against the limits and neither holds the cooldown.
		if challengeID == "" {
			a.refundThrottle(ctx, []string{"mfa-open:" + sess.UserID})

			if cooldownKey != "" {
				_ = a.challenges.Delete(ctx, cooldownKey)
			}
		}

		if err != nil {
			return NewOAuthErrorFrom(err)
		}

		if challengeID != "" {
			if _, err := a.challenges.Increment(ctx, sess.ID+":"+method, 1,
				cache.TTL[int64](time.Until(sess.ExpiresAt))); err != nil {
				return NewOAuthErrorFrom(err)
			}

			a.failThrottle(ctx, []string{"mfa-open:" + sess.UserID})
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

// issueStepToken mints a step token bound to the pending sess, returning it with its jti.
func (a *Auth) issueStepToken(ctx context.Context, sess *session.Session, cl *client.Client) (string, string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", "", NewOAuthErrorFrom(err)
	}

	if err := a.jti.Issue(ctx, jti, sess.ID, time.Until(sess.ExpiresAt)); err != nil {
		return "", "", NewOAuthErrorFrom(err)
	}

	tok, err := a.codec.Encrypt(token.AccessClaims{
		Type:      token.TypeStepToken,
		SessionID: sess.ID,
		TokenID:   jti,
		ClientID:  cl.ID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: sess.ExpiresAt.Unix(),
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

	if !slices.Contains(statuses, sess.Status) {
		return nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	cl, err := a.clients.GetClient(ctx, sess.ClientID)
	if err != nil {
		return nil, NewOAuthErrorFrom(err)
	}

	sc := &stepContext{sess: sess, claims: claims, client: cl}

	if sess.Status == session.StatusActive {
		return sc, nil
	}

	st, err := a.pending.Get(ctx, sess.ID)
	if err != nil {
		var knf cache.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil, NewOAuthErrorFrom(token.ErrInvalidToken)
		}

		return nil, NewOAuthErrorFrom(err)
	}

	if !st.Initialized {
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

	st, err := a.evaluateSteps(ctx, sess, sc.client, req)
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

	var cookie, jti string

	// A session still pending after a step gets a fresh cookie and step token
	if sess.Status != session.StatusActive {
		if err := a.Transaction.Run(ctx, func(ctx context.Context) error {
			if err := a.sessions.Update(ctx, sess); err != nil {
				return err
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
			return LoginResult{}, NewOAuthErrorFrom(err)
		}

		st.TokenIDs = []string{jti}

		return a.pendingLoginResult(ctx, sess, sc.client, st, cookie, returnTo, baseURL, mountPath)
	}

	sess.ExpiresAt = now.Add(a.config.SessionTTL)

	if err := a.Transaction.Run(ctx, func(ctx context.Context) error {
		if err := a.sessions.Update(ctx, sess); err != nil {
			return err
		}

		for _, id := range retired {
			if err := a.jti.Revoke(ctx, id); err != nil {
				return err
			}
		}

		var err error

		cookie, _, err = a.issueSessionCookie(ctx, sess, now, sess.ExpiresAt)

		return err
	}); err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	_ = deleteSynced(ctx, a.pending, sess.ID)

	a.emit(ctx, event.Event{Type: event.TypeLoginSuccess, UserID: sess.UserID, ClientID: sess.ClientID, Detail: map[string]any{"step": "completed"}})

	return a.buildLoginResult(ctx, sess, sc.client, returnTo, cookie, baseURL, mountPath)
}

// checkThrottle claims an attempt on every key, refusing (and refunding the claims made so
// far) when any key is exhausted or locked out.
func (a *Auth) checkThrottle(ctx context.Context, keys []string, clientID, ip string) error {
	for i, key := range keys {
		ok, retryAfter, err := a.throttle.Allow(ctx, key)
		if err != nil {
			a.refundThrottle(ctx, keys[:i])

			return NewOAuthErrorFrom(err)
		}

		if !ok {
			a.refundThrottle(ctx, keys[:i])
			a.emit(ctx, event.Event{Type: event.TypeLockout, ClientID: clientID, IP: ip, Detail: map[string]any{"key": key}})

			return NewThrottledError(retryAfter)
		}
	}

	return nil
}

// refundThrottle returns the claims on every key when the attempt was not a guess.
func (a *Auth) refundThrottle(ctx context.Context, keys []string) {
	for _, key := range keys {
		_ = a.throttle.Refund(ctx, key)
	}
}

// passThrottle settles a successful attempt: the identity key is cleared and the source keys
// are refunded, so successes never count against a shared source.
func (a *Auth) passThrottle(ctx context.Context, keys []string) {
	if len(keys) == 0 {
		return
	}

	a.resetThrottle(ctx, keys[:1])
	a.refundThrottle(ctx, keys[1:])
}

// failThrottle records a failed attempt on every key.
func (a *Auth) failThrottle(ctx context.Context, keys []string) {
	for _, key := range keys {
		_ = a.throttle.Fail(ctx, key)
	}
}

// resetThrottle clears every key after a successful attempt.
func (a *Auth) resetThrottle(ctx context.Context, keys []string) {
	for _, key := range keys {
		_ = a.throttle.Reset(ctx, key)
	}
}

// throttleKeys combines a stable identity key with the caller's IP.
func throttleKeys(identity, ip string) []string {
	keys := make([]string, 0, 2)

	if identity != "" {
		keys = append(keys, identity)
	}

	if ip != "" {
		keys = append(keys, "ip:"+ip)
	}

	return keys
}
