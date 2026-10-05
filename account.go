package auth

import (
	"context"
	"errors"

	"azugo.io/auth/client"
	"azugo.io/auth/event"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/core/http"
)

// RegisterRequest carries a self-registration and the request-derived values.
type RegisterRequest struct {
	Credentials ClientCredentials
	Username    string
	Email       string
	Password    string
	// Extra is passed through to Registerer.Register uninterpreted.
	Extra     map[string]any
	ReturnTo  string
	BaseURL   string
	MountPath string
	IP        string
}

// RegisterResult is returned by Register.
type RegisterResult struct {
	UserID string
	// Login is set when the client's RegistrationPolicy signs the new account in.
	Login *LoginResult
}

// PasswordChangeRequest carries a password change for the session behind Token.
type PasswordChangeRequest struct {
	// Token is an active session credential, or the step token (or pending cookie) of a
	// pending_password_change session.
	Token string
	// CurrentPassword is verified on an active session only.
	CurrentPassword string
	NewPassword     string
	// KeepOtherSessions leaves the account's other sessions valid after a self-service change;
	// by default they are revoked.
	KeepOtherSessions bool
	ReturnTo          string
	BaseURL           string
	MountPath         string
	IP                string
}

// Register creates a new account through the Registerer under the client's
// RegistrationPolicy, signing it in like a password login when the policy says so.
func (a *Auth) Register(ctx context.Context, in RegisterRequest) (RegisterResult, error) {
	reg, ok := a.users.(Registerer)
	if !ok {
		return RegisterResult{}, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "registration is not enabled")
	}

	cl, err := a.AuthenticateClient(ctx, in.Credentials, in.BaseURL, in.MountPath)
	if err != nil {
		return RegisterResult{}, err
	}

	// Check allowed registration policies
	if cl.RegistrationPolicy != client.RegistrationPolicyRequireLogin && cl.RegistrationPolicy != client.RegistrationPolicySignIn {
		return RegisterResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeUnauthorizedClient, "client does not allow registration")
	}

	if cl.RegistrationPolicy == client.RegistrationPolicySignIn && (!cl.GrantTypeAllowed(client.GrantTypePassword) || !cl.AuthMethodAllowed(client.AuthMethodPassword)) {
		return RegisterResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeUnauthorizedClient, "client is not allowed to sign in with a password")
	}

	if in.Password == "" || (in.Username == "" && in.Email == "") {
		return RegisterResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "username or email and password are required")
	}

	if err := a.passwords.Validate(ctx, in.Password, UserInfo{Email: in.Email, Claims: map[string]any{"preferred_username": in.Username}}); err != nil {
		return RegisterResult{}, NewOAuthErrorFrom(err)
	}

	// Registration throttle
	if in.IP != "" {
		ok, retryAfter, err := a.registrations.Allow(ctx, in.IP)
		if err != nil {
			return RegisterResult{}, NewOAuthErrorFrom(err)
		}

		if !ok {
			a.emit(ctx, event.Event{Type: event.TypeLockout, ClientID: cl.ID, IP: in.IP, Detail: map[string]any{"key": "register"}})

			return RegisterResult{}, NewThrottledError(retryAfter)
		}
	}

	info, err := reg.Register(ctx, RegistrationRequest{Username: in.Username, Email: in.Email, Password: in.Password, Extra: in.Extra})
	if err != nil {
		return RegisterResult{}, NewOAuthErrorFrom(err)
	}

	a.emit(ctx, event.Event{Type: event.TypeUserRegistered, UserID: info.ID, ClientID: cl.ID, IP: in.IP, Detail: map[string]any{"username": in.Username}})

	if cl.RegistrationPolicy != client.RegistrationPolicySignIn {
		return RegisterResult{UserID: info.ID}, nil
	}

	sess := &session.Session{
		UserID:   info.ID,
		ClientID: cl.ID,
		Scope:    clientScope(cl, info.Scope),
		AMR:      mergeAMR([]string{amrPassword}, info.AMR),
	}

	login, err := a.startSession(ctx, sess, cl, acrRequest{}, in.ReturnTo, in.BaseURL, in.MountPath)
	if err != nil {
		return RegisterResult{}, err
	}

	return RegisterResult{UserID: info.ID, Login: &login}, nil
}

// ChangePassword sets a new password for the session behind the Token.
func (a *Auth) ChangePassword(ctx context.Context, in PasswordChangeRequest) (LoginResult, error) {
	changer, ok := a.users.(PasswordChanger)
	if !ok {
		return LoginResult{}, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "password change is not enabled")
	}

	if in.NewPassword == "" {
		return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "new password is required")
	}

	sc, err := a.stepSession(ctx, in.Token, session.StatusActive, session.StatusPendingPasswordChange)
	if err != nil {
		return LoginResult{}, err
	}

	info, err := a.users.GetUser(ctx, sc.sess.UserID)
	if err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	if sc.sess.Status == session.StatusPendingPasswordChange {
		if !info.RequiresPasswordChange {
			return LoginResult{}, NewOAuthErrorFrom(token.ErrInvalidToken)
		}

		if err := a.passwords.Validate(ctx, in.NewPassword, info); err != nil {
			return LoginResult{}, NewOAuthErrorFrom(err)
		}

		if err := changer.SetPassword(ctx, sc.sess.UserID, in.NewPassword); err != nil {
			return LoginResult{}, NewOAuthErrorFrom(err)
		}

		a.emit(ctx, event.Event{Type: event.TypePasswordChanged, UserID: sc.sess.UserID, ClientID: sc.client.ID, IP: in.IP, Detail: map[string]any{"forced": true}})

		return a.advanceSession(ctx, sc, in.ReturnTo, in.BaseURL, in.MountPath)
	}

	if in.CurrentPassword == "" {
		return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "current password is required")
	}

	if err := a.passwords.Validate(ctx, in.NewPassword, info); err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	keys := throttleKeys("pwdchange:"+sc.sess.UserID, in.IP)

	if err := a.checkThrottle(ctx, keys, sc.client.ID, in.IP); err != nil {
		return LoginResult{}, err
	}

	if err := changer.ChangePassword(ctx, sc.sess.UserID, in.CurrentPassword, in.NewPassword); err != nil {
		mapped := NewOAuthErrorFrom(err)

		var oe *OAuthError

		switch {
		case errors.Is(err, ErrInvalidCredentials):
			a.failThrottle(ctx, keys)
		case errors.As(mapped, &oe) && oe.StatusCode() >= http.StatusInternalServerError:
			a.refundThrottle(ctx, keys)
		}

		return LoginResult{}, mapped
	}

	a.passThrottle(ctx, keys)
	a.emit(ctx, event.Event{Type: event.TypePasswordChanged, UserID: sc.sess.UserID, ClientID: sc.client.ID, IP: in.IP})

	// Any other session may be the reason the password is being changed.
	if !in.KeepOtherSessions {
		if err := a.revokeOtherSessions(ctx, sc.sess.UserID, sc.sess.ID); err != nil {
			return LoginResult{}, err
		}
	}

	res := LoginResult{Status: sc.sess.Status, ACR: sc.sess.ACR, AMR: sc.sess.AMR}

	if sc.client.ResponseMode == client.ResponseModeRedirect {
		res.ReturnTo = safeLocalRedirect(in.ReturnTo)
	}

	return res, nil
}

// revokeOtherSessions revokes every valid session of userID but current.
func (a *Auth) revokeOtherSessions(ctx context.Context, userID, sessionID string) error {
	lister, ok := a.sessions.(session.Lister)
	if !ok {
		return nil
	}

	sessions, _, err := lister.List(ctx, userID, nil, nil)
	if err != nil {
		return NewOAuthErrorFrom(err)
	}

	for _, s := range sessions {
		if s.ID == sessionID || !s.Valid() {
			continue
		}

		if err := a.sessions.Revoke(ctx, s.ID); err != nil && !errors.Is(err, session.ErrNotFound) {
			return NewOAuthErrorFrom(err)
		}

		_ = deleteSynced(ctx, a.fedIDTokens, s.ID)
	}

	return nil
}

// Profile returns the caller's profile data from the ProfileManager.
func (a *Auth) Profile(ctx context.Context, tok string) (map[string]any, error) {
	pm, ok := a.users.(ProfileManager)
	if !ok {
		return nil, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "profile management is not enabled")
	}

	info, _, err := a.IntrospectFirstParty(ctx, tok)
	if err != nil {
		return nil, err
	}

	data, err := pm.GetProfile(ctx, info.ID)
	if err != nil {
		return nil, NewOAuthErrorFrom(err)
	}

	return data, nil
}

// UpdateProfile stores the caller's profile data through the ProfileManager.
func (a *Auth) UpdateProfile(ctx context.Context, tok string, data map[string]any) error {
	pm, ok := a.users.(ProfileManager)
	if !ok {
		return NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "profile management is not enabled")
	}

	info, _, err := a.IntrospectFirstParty(ctx, tok)
	if err != nil {
		return err
	}

	if err := pm.UpdateProfile(ctx, info.ID, data); err != nil {
		return NewOAuthErrorFrom(err)
	}

	return nil
}
