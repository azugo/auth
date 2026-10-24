package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/event"
	"azugo.io/auth/reset"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/core/http"
	"go.uber.org/zap"
)

// RegisterRequest carries a self-registration and the request-derived values.
type RegisterRequest struct {
	Credentials ClientCredentials
	Username    string
	Password    string
	// Contacts maps a channel to the address given for it.
	Contacts map[string]string
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
	// Accepted is the uniform answer given for an address on a verified channel.
	Accepted bool
	// Request is the contact verification request to present the delivered proof with.
	Request     string
	Interaction string
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
	// RevokeAPIKeys revokes the account's API keys after a password change; by default they stay
	// valid.
	RevokeAPIKeys bool
	ReturnTo      string
	BaseURL       string
	MountPath     string
	IP            string
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

	if in.Password == "" {
		return RegisterResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "password is required")
	}

	if len(in.Contacts) > 8 {
		return RegisterResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "too many contacts")
	}

	for channel, address := range in.Contacts {
		if len(channel) == 0 || len(channel) > 32 || strings.Trim(channel, "abcdefghijklmnopqrstuvwxyz0123456789_-") != "" {
			return RegisterResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "invalid contact channel")
		}

		if len(address) > 4096 {
			return RegisterResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "contact address is too long")
		}
	}

	// The user provider receives every address in its canonical form.
	contacts := make(map[string]string, len(in.Contacts))
	identified := in.Username != ""

	for channel, address := range in.Contacts {
		if address = a.NormalizeAddress(channel, address); address != "" {
			contacts[channel] = address
			identified = true
		}
	}

	in.Contacts = contacts

	if !identified {
		return RegisterResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "username or contact address is required")
	}

	// The first verified channel the registration gives an address for answers uniformly.
	var contact *contactStep

	for _, c := range a.contacts {
		if in.Contacts[c.channel] != "" {
			contact = c

			break
		}
	}

	given := UserInfo{Contacts: make(map[string][]Contact, len(in.Contacts)), Claims: map[string]any{"preferred_username": in.Username}}
	for channel, address := range in.Contacts {
		given.Contacts[channel] = []Contact{{Address: address}}
	}

	if err := a.passwords.Validate(ctx, in.Password, given); err != nil {
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

	info, err := reg.Register(ctx, RegistrationRequest{Username: in.Username, Password: in.Password, Contacts: in.Contacts, Extra: in.Extra})

	// Only the owner of the verified address learns whether the account was new: a new account
	// gets the verification secret, the owner of a taken verified address a password reset.
	if contact != nil {
		// A decoy stands in wherever no verification is opened, so the answer is alike.
		request, jerr := newJTI()
		if jerr != nil {
			return RegisterResult{}, NewOAuthErrorFrom(jerr)
		}

		switch {
		case errors.Is(err, ErrUsernameTaken):
			return RegisterResult{}, NewOAuthErrorFrom(err)
		case errors.Is(err, ErrUserAlreadyExists):
			channel := contact.channel

			if taken, ok := errors.AsType[*ContactTakenError](err); ok {
				channel = taken.Channel
			}

			// A conflict on a channel without verification is already answered openly there.
			if a.contactStep(channel) == nil || in.Contacts[channel] == "" {
				return RegisterResult{}, NewOAuthErrorFrom(err)
			}

			a.notifyExistingAccount(ctx, cl, channel, in.Contacts[channel], in.IP)
		case err != nil:
			return RegisterResult{}, NewOAuthErrorFrom(err)
		default:
			a.emit(ctx, event.Event{Type: event.TypeUserRegistered, UserID: info.ID, ClientID: cl.ID, IP: in.IP, Detail: map[string]any{"username": in.Username}})

			preferred, _ := info.PreferredContact(contact.channel)

			address := preferred.Address
			if address == "" {
				address = in.Contacts[contact.channel]
			}

			if req, err := contact.open(ctx, info, address, cl.ID); err != nil {
				a.Log(ctx).Error("failed to open contact verification", zap.String("user.id", info.ID), zap.String("channel", contact.channel), zap.Error(err))
			} else {
				request = req.ID
			}
		}

		return RegisterResult{Accepted: true, Request: request, Interaction: reset.MethodInteraction(contact.method)}, nil
	}

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

// notifyExistingAccount opens a password reset for the account already registered under address
// through the first of the client's reset methods that can deliver to it.
func (a *Auth) notifyExistingAccount(ctx context.Context, cl *client.Client, channel, address, ip string) {
	if _, ok := a.users.(PasswordResetter); !ok || !cl.GrantTypeAllowed(client.GrantTypePassword) || !cl.AuthMethodAllowed(client.AuthMethodPassword) {
		return
	}

	available, err := a.resetMethodsFor(ctx, cl)
	if err != nil || len(available) == 0 {
		return
	}

	verifier, _ := a.users.(ContactVerifier)

	info, err := verifier.FindContact(ctx, channel, address)
	if err != nil {
		if !errors.Is(err, ErrUserNotFound) {
			a.Log(ctx).Error("failed to find registered account", zap.Error(err))
		}

		return
	}

	id, err := newJTI()
	if err != nil {
		return
	}

	now := time.Now()
	req := &reset.Request{
		ID:           id,
		UserID:       info.ID,
		Identifier:   address,
		ClientID:     cl.ID,
		Registration: true,
		CreatedAt:    now,
		ExpiresAt:    now.Add(a.config.PasswordResetTTL),
	}

	for _, method := range available {
		m, err := a.resetMethods.Get(ctx, method)
		if err != nil {
			a.Log(ctx).Error("failed to load password reset method", zap.String("method", method), zap.Error(err))

			continue
		}

		if a.openResetChallenge(ctx, req, m, method, info); req.ChallengeID != "" {
			break
		}
	}

	if req.ChallengeID == "" {
		return
	}

	if err := a.resets.Save(ctx, req); err != nil {
		a.Log(ctx).Error("failed to save password reset request", zap.String("user.id", info.ID), zap.Error(err))

		return
	}

	a.emit(ctx, event.Event{
		Type:     event.TypePasswordResetRequested,
		UserID:   info.ID,
		ClientID: cl.ID,
		IP:       ip,
		Detail: map[string]any{
			"identifier":   address,
			"method":       req.Method,
			"delivered":    true,
			"registration": true,
		},
	})
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

		var revoked []string

		// The new password and the revocations it asks for are stored together.
		if err := a.Transaction.Run(ctx, func(ctx context.Context) error {
			revoked = nil

			if err := changer.SetPassword(ctx, sc.sess.UserID, in.NewPassword); err != nil {
				return err
			}

			if !in.RevokeAPIKeys || a.apiKeys == nil {
				return nil
			}

			var err error

			revoked, err = a.apiKeys.RevokeAll(ctx, sc.sess.UserID)

			return err
		}); err != nil {
			return LoginResult{}, NewOAuthErrorFrom(err)
		}

		a.emit(ctx, event.Event{Type: event.TypePasswordChanged, UserID: sc.sess.UserID, ClientID: sc.client.ID, IP: in.IP, Detail: map[string]any{"forced": true}})

		for _, id := range revoked {
			a.emit(ctx, event.Event{Type: event.TypeAPIKeyRevoked, UserID: sc.sess.UserID, ClientID: sc.client.ID, IP: in.IP, Detail: map[string]any{"key_id": id}})
		}

		return a.advanceSession(ctx, sc, in.ReturnTo, in.BaseURL, in.MountPath)
	}

	if in.CurrentPassword == "" {
		return LoginResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "current password is required")
	}

	if err := a.passwords.Validate(ctx, in.NewPassword, info); err != nil {
		return LoginResult{}, NewOAuthErrorFrom(err)
	}

	// Checked before the current password is guessed
	if err := a.checkStepUp(ctx, sc.sess, ActionChangePassword); err != nil {
		return LoginResult{}, err
	}

	identity := "pwdchange:" + sc.sess.UserID
	keys := throttleKeys(identity, in.IP)

	if err := a.checkThrottle(ctx, keys, sc.client.ID, in.IP); err != nil {
		return LoginResult{}, err
	}

	var (
		sessions []string
		revoked  []string
	)

	// The new password and the revocations it asks for are stored together.
	err = a.Transaction.Run(ctx, func(ctx context.Context) error {
		sessions = nil
		revoked = nil

		err := changer.ChangePassword(ctx, sc.sess.UserID, in.CurrentPassword, in.NewPassword)
		if err != nil {
			return err
		}

		// Any other session may be the reason the password is being changed.
		if !in.KeepOtherSessions {
			if sessions, err = a.revokeOtherSessions(ctx, sc.sess.UserID, sc.sess.ID); err != nil {
				return err
			}
		}

		if !in.RevokeAPIKeys || a.apiKeys == nil {
			return nil
		}

		revoked, err = a.apiKeys.RevokeAll(ctx, sc.sess.UserID)

		return err
	})
	if err != nil {
		mapped := NewOAuthErrorFrom(err)
		oe, isOAuth := errors.AsType[*OAuthError](mapped)

		switch {
		case errors.Is(err, ErrInvalidCredentials):
			a.failThrottle(ctx, keys)
		case isOAuth && oe.StatusCode() >= http.StatusInternalServerError:
			a.refundThrottle(ctx, keys)
		}

		return LoginResult{}, mapped
	}

	a.passThrottle(ctx, keys, identity)

	for _, id := range sessions {
		_ = deleteSynced(ctx, a.fedIDTokens, id)
	}

	a.emit(ctx, event.Event{Type: event.TypePasswordChanged, UserID: sc.sess.UserID, ClientID: sc.client.ID, IP: in.IP})

	for _, id := range revoked {
		a.emit(ctx, event.Event{Type: event.TypeAPIKeyRevoked, UserID: sc.sess.UserID, ClientID: sc.client.ID, IP: in.IP, Detail: map[string]any{"key_id": id}})
	}

	res := LoginResult{Status: sc.sess.Status, ACR: sc.sess.ACR, AMR: sc.sess.AMR}

	if sc.client.ResponseMode == client.ResponseModeRedirect {
		res.ReturnTo = safeLocalRedirect(in.ReturnTo)
	}

	return res, nil
}

// revokeOtherSessions revokes every valid session of userID but current and returns their IDs.
func (a *Auth) revokeOtherSessions(ctx context.Context, userID, sessionID string) ([]string, error) {
	lister, ok := a.sessions.(session.Lister)
	if !ok {
		return nil, nil
	}

	sessions, _, err := lister.List(ctx, userID, nil, nil)
	if err != nil {
		return nil, NewOAuthErrorFrom(err)
	}

	revoked := make([]string, 0, len(sessions))

	for _, s := range sessions {
		if s.ID == sessionID || !s.Valid() {
			continue
		}

		if err := a.sessions.Revoke(ctx, s.ID); err != nil && !errors.Is(err, session.ErrNotFound) {
			return nil, NewOAuthErrorFrom(err)
		}

		revoked = append(revoked, s.ID)
	}

	return revoked, nil
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

	info, err := a.RequireStepUp(ctx, tok, ActionUpdateProfile)
	if err != nil {
		return err
	}

	if err := pm.UpdateProfile(ctx, info.ID, data); err != nil {
		return NewOAuthErrorFrom(err)
	}

	return nil
}
