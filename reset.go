package auth

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/event"
	"azugo.io/auth/reset"
	"azugo.io/auth/session"

	"azugo.io/core/cache"
	"azugo.io/core/http"
	"go.uber.org/zap"
)

// PasswordResetRequest carries an unauthenticated password-reset request.
type PasswordResetRequest struct {
	Credentials ClientCredentials
	// Identifier is the username or email of the account.
	Identifier string
	// Method selects the reset method; empty = the first the client offers.
	Method    string
	BaseURL   string
	MountPath string
	IP        string
}

// PasswordResetStepRequest carries a call against a reset in progress.
type PasswordResetStepRequest struct {
	// Token is the reset_token handed out by RequestPasswordReset.
	Token string
	// Method switches the reset to another method; empty = re-open the selected one.
	Method string
	IP     string
}

// PasswordResetConfirmRequest carries the proof of ownership with the new password.
type PasswordResetConfirmRequest struct {
	Token string
	// Response is the method-specific proof, e.g. {"code":"123456"} or {"token":"..."}; nil
	// for an approved asynchronous method.
	Response    map[string]any
	NewPassword string
	ReturnTo    string
	BaseURL     string
	MountPath   string
	IP          string
}

// PasswordResetResult describes a reset in progress.
type PasswordResetResult struct {
	// Status is reset.VerifyPending until an asynchronous method reports reset.VerifyApproved.
	Status reset.VerifyResult
	// Token is the reset_token the caller presents to the step and confirm calls.
	Token string
	// Available, Selected, Interaction and Data describe the prompt, like a pending MFA step.
	Available   []string
	Selected    string
	Interaction string
	Data        map[string]any
}

// resetMethodsFor returns the reset method names the client offers.
func (a *Auth) resetMethodsFor(ctx context.Context, cl *client.Client) ([]string, error) {
	names, err := a.resetMethods.Names(ctx)
	if err != nil {
		return nil, err
	}

	if len(cl.AllowedPasswordResetMethods) == 0 {
		return names, nil
	}

	return slices.DeleteFunc(names, func(n string) bool { return !slices.Contains(cl.AllowedPasswordResetMethods, n) }), nil
}

func (a *Auth) openResetChallenge(ctx context.Context, req *reset.Request, m reset.Method, method string, info UserInfo) {
	req.Method = method
	req.ChallengeID = ""
	req.Data = nil
	req.Approved = false

	if info.ID == "" {
		return
	}

	challengeID, data, err := m.Begin(ctx, req, info)
	if err != nil {
		if !errors.Is(err, reset.ErrUnavailable) {
			a.Log(ctx).Error("failed to open password reset challenge", zap.String("user.id", req.UserID), zap.String("method", method), zap.Error(err))
		}

		return
	}

	req.ChallengeID = challengeID
	req.Data = data
}

func resetResult(req *reset.Request, m reset.Method, available []string) PasswordResetResult {
	res := PasswordResetResult{Status: reset.VerifyPending, Token: req.ID, Available: available, Selected: req.Method, Interaction: reset.MethodInteraction(m), Data: req.Data}
	if req.Approved {
		res.Status = reset.VerifyApproved
	}

	return res
}

// RequestPasswordReset opens a reset for the account behind Identifier with the selected
// method and returns the reset_token to continue with.
func (a *Auth) RequestPasswordReset(ctx context.Context, in PasswordResetRequest) (PasswordResetResult, error) {
	resetter, ok := a.users.(PasswordResetter)
	if !ok {
		return PasswordResetResult{}, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "password reset is not enabled")
	}

	cl, err := a.AuthenticateClient(ctx, in.Credentials, in.BaseURL, in.MountPath)
	if err != nil {
		return PasswordResetResult{}, err
	}

	// The confirmation signs the user in like a password login.
	if !cl.GrantTypeAllowed(client.GrantTypePassword) || !cl.AuthMethodAllowed(client.AuthMethodPassword) {
		return PasswordResetResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeUnauthorizedClient, "client is not allowed to use the password grant")
	}

	if in.Identifier == "" {
		return PasswordResetResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "identifier is required")
	}

	available, err := a.resetMethodsFor(ctx, cl)
	if err != nil {
		return PasswordResetResult{}, NewOAuthErrorFrom(err)
	}

	if len(available) == 0 {
		return PasswordResetResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "no password reset method is available")
	}

	method := cmp.Or(in.Method, available[0])
	if !slices.Contains(available, method) {
		return PasswordResetResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "password reset method is not available")
	}

	m, err := a.resetMethods.Get(ctx, method)
	if err != nil {
		return PasswordResetResult{}, NewOAuthErrorFrom(err)
	}

	keys := []string{throttleIdentity("reset:", in.Identifier)}
	if in.IP != "" {
		keys = append(keys, "reset-ip:"+in.IP)
	}

	if err := a.checkThrottle(ctx, keys, cl.ID, in.IP); err != nil {
		return PasswordResetResult{}, err
	}

	id, err := newJTI()
	if err != nil {
		return PasswordResetResult{}, NewOAuthErrorFrom(err)
	}

	now := time.Now()
	req := &reset.Request{ID: id, Identifier: in.Identifier, ClientID: cl.ID, CreatedAt: now, ExpiresAt: now.Add(a.config.PasswordResetTTL)}

	info, err := resetter.FindUser(ctx, in.Identifier)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return PasswordResetResult{}, NewOAuthErrorFrom(err)
	}

	req.UserID = info.ID
	a.openResetChallenge(ctx, req, m, method, info)

	if err := a.resets.Save(ctx, req); err != nil {
		return PasswordResetResult{}, NewOAuthErrorFrom(err)
	}

	detail := map[string]any{"identifier": in.Identifier, "method": method, "delivered": req.ChallengeID != ""}
	a.emit(ctx, event.Event{Type: event.TypePasswordResetRequested, UserID: req.UserID, ClientID: cl.ID, IP: in.IP, Detail: detail})

	return resetResult(req, m, available), nil
}

// resetRequest resolves a reset_token to its live request and client.
func (a *Auth) resetRequest(ctx context.Context, tok string) (*reset.Request, *client.Client, error) {
	if a.resets == nil {
		return nil, nil, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "password reset is not enabled")
	}

	if tok == "" {
		return nil, nil, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "reset token is required")
	}

	req, err := a.resets.Get(ctx, tok)
	if err != nil {
		if errors.Is(err, reset.ErrNotFound) {
			return nil, nil, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "invalid or expired reset request")
		}

		return nil, nil, NewOAuthErrorFrom(err)
	}

	cl, err := a.clients.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, nil, NewOAuthErrorFrom(err)
	}

	return req, cl, nil
}

// BeginPasswordReset switches a reset in progress to another method.
func (a *Auth) BeginPasswordReset(ctx context.Context, in PasswordResetStepRequest) (PasswordResetResult, error) {
	req, cl, err := a.resetRequest(ctx, in.Token)
	if err != nil {
		return PasswordResetResult{}, err
	}

	available, err := a.resetMethodsFor(ctx, cl)
	if err != nil {
		return PasswordResetResult{}, NewOAuthErrorFrom(err)
	}

	method := cmp.Or(in.Method, req.Method)
	if !slices.Contains(available, method) {
		return PasswordResetResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "password reset method is not available")
	}

	m, err := a.resetMethods.Get(ctx, method)
	if err != nil {
		return PasswordResetResult{}, NewOAuthErrorFrom(err)
	}

	budget := throttleIdentity("reset-open:", req.Identifier)

	if _, err := a.limitChallenge(ctx, req.ID, budget, req.ExpiresAt, cl.ID, method); err != nil {
		return PasswordResetResult{}, err
	}

	if _, err := a.challenges.Increment(ctx, req.ID+":"+method, 1, cache.TTL[int64](time.Until(req.ExpiresAt))); err != nil {
		return PasswordResetResult{}, NewOAuthErrorFrom(err)
	}

	a.failThrottle(ctx, []string{budget})

	var info UserInfo

	if !req.Decoy() {
		if info, err = a.users.GetUser(ctx, req.UserID); err != nil && !errors.Is(err, ErrUserNotFound) {
			a.Log(ctx).Error("failed to load account for password reset", zap.String("user.id", req.UserID), zap.Error(err))
		}
	}

	a.openResetChallenge(ctx, req, m, method, info)

	if err := a.resets.Update(ctx, req); err != nil {
		return PasswordResetResult{}, NewOAuthErrorFrom(err)
	}

	return resetResult(req, m, available), nil
}

// PasswordResetStatus polls an asynchronous method: an approval is recorded on the request.
func (a *Auth) PasswordResetStatus(ctx context.Context, in PasswordResetStepRequest) (PasswordResetResult, error) {
	req, cl, err := a.resetRequest(ctx, in.Token)
	if err != nil {
		return PasswordResetResult{}, err
	}

	available, err := a.resetMethodsFor(ctx, cl)
	if err != nil {
		return PasswordResetResult{}, NewOAuthErrorFrom(err)
	}

	m, err := a.resetMethods.Get(ctx, req.Method)
	if err != nil {
		return PasswordResetResult{}, NewOAuthErrorFrom(err)
	}

	if req.Approved || req.Decoy() || req.ChallengeID == "" || reset.MethodInteraction(m) != reset.InteractionPoll {
		return resetResult(req, m, available), nil
	}

	info, err := a.users.GetUser(ctx, req.UserID)
	if err != nil {
		return PasswordResetResult{}, NewOAuthErrorFrom(err)
	}

	v, err := m.Verify(ctx, req, info, nil)
	if err != nil {
		return PasswordResetResult{}, NewOAuthErrorFrom(err)
	}

	switch v {
	case reset.VerifyApproved:
		req.Approved = true

		if err := a.resets.Update(ctx, req); err != nil {
			return PasswordResetResult{}, NewOAuthErrorFrom(err)
		}
	case reset.VerifyDenied:
		_, _ = a.resets.Consume(ctx, req.ID)
		a.emit(ctx, event.Event{Type: event.TypePasswordResetFailure, UserID: req.UserID, ClientID: cl.ID, IP: in.IP, Detail: map[string]any{"method": req.Method}})

		return PasswordResetResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "password reset was denied")
	case reset.VerifyPending:
	}

	return resetResult(req, m, available), nil
}

// ResetPassword verifies the proof of ownership, sets the new password, revokes the account's
// other sessions (when the session store is a Lister) and signs the user in like a password
// login.
func (a *Auth) ResetPassword(ctx context.Context, in PasswordResetConfirmRequest) (LoginResult, error) {
	resetter, ok := a.users.(PasswordResetter)
	if !ok {
		return LoginResult{}, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "password reset is not enabled")
	}

	if in.NewPassword == "" {
		return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "new password is required")
	}

	// The token is hashed into the key so a lockout event never carries it
	keys := throttleKeys(fmt.Sprintf("reset-verify:%x", sha256.Sum256([]byte(in.Token))), in.IP)

	if err := a.checkThrottle(ctx, keys, "", in.IP); err != nil {
		return LoginResult{}, err
	}

	req, cl, err := a.resetRequest(ctx, in.Token)
	if err != nil {
		a.failThrottle(ctx, keys)

		return LoginResult{}, err
	}

	m, err := a.resetMethods.Get(ctx, req.Method)
	if err != nil {
		a.refundThrottle(ctx, keys)

		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	// A decoy answers exactly like a real request whose proof is wrong, or still pending.
	if req.Decoy() {
		if in.Response == nil && reset.MethodInteraction(m) == reset.InteractionPoll {
			a.refundThrottle(ctx, keys)

			return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "password reset is awaiting approval")
		}

		a.failThrottle(ctx, keys)

		return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "invalid password reset response")
	}

	info, err := a.users.GetUser(ctx, req.UserID)
	if err != nil {
		a.refundThrottle(ctx, keys)

		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	if !req.Approved {
		v, err := m.Verify(ctx, req, info, in.Response)
		if err != nil {
			a.refundThrottle(ctx, keys)

			return LoginResult{}, NewOAuthErrorFrom(err)
		}

		switch v {
		case reset.VerifyDenied:
			a.failThrottle(ctx, keys)
			a.emit(ctx, event.Event{Type: event.TypePasswordResetFailure, UserID: info.ID, ClientID: cl.ID, IP: in.IP, Detail: map[string]any{"method": req.Method}})

			return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "invalid password reset response")
		case reset.VerifyPending:
			a.refundThrottle(ctx, keys)

			return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "password reset is awaiting approval")
		case reset.VerifyApproved:
		}
	}

	a.passThrottle(ctx, keys)

	// The policy runs only for a proven owner, so it cannot tell a decoy from a real request
	if err := a.passwords.Validate(ctx, in.NewPassword, info); err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	// Consume is the single-use guarantee
	if _, err := a.resets.Consume(ctx, req.ID); err != nil {
		if errors.Is(err, reset.ErrNotFound) {
			return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "invalid or expired reset request")
		}

		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	if err := resetter.ResetPassword(ctx, info.ID, in.NewPassword); err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	a.emit(ctx, event.Event{Type: event.TypePasswordReset, UserID: info.ID, ClientID: cl.ID, IP: in.IP, Detail: map[string]any{"method": req.Method}})

	// Whoever held the old password may hold a session too, a parked step included.
	if err := a.revokeOtherSessions(ctx, info.ID, ""); err != nil {
		return LoginResult{}, err
	}

	sess := &session.Session{
		UserID:   info.ID,
		ClientID: cl.ID,
		Scope:    clientScope(cl, info.Scope),
		AMR:      mergeAMR([]string{amrPassword}, info.AMR),
	}

	return a.startSession(ctx, sess, cl, acrRequest{}, in.ReturnTo, in.BaseURL, in.MountPath)
}
