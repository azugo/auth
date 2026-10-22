package auth

import (
	"context"
	"errors"

	"azugo.io/auth/contact"
	"azugo.io/auth/event"
	"azugo.io/auth/reset"
	"azugo.io/auth/session"

	"azugo.io/core/http"
)

// ContactRequest carries a contact change for the active session behind Token.
type ContactRequest struct {
	Token   string
	Channel string
	Address string
	IP      string
}

// ContactVerificationResult describes a contact verification in progress.
type ContactVerificationResult struct {
	// Request is the verification request ID the proof is presented with.
	Request string
	// Interaction and Data describe the prompt, like a pending reset.
	Interaction string
	Data        map[string]any
}

// AddContact starts the verification of a new address on a channel for the caller's account;
// the address joins the account only once the proof is presented, see VerifyContact.
func (a *Auth) AddContact(ctx context.Context, in ContactRequest) (ContactVerificationResult, error) {
	c := a.contactStep(in.Channel)
	if c == nil {
		return ContactVerificationResult{}, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "contact channel is not enabled")
	}

	in.Address = a.NormalizeAddress(in.Channel, in.Address)

	if in.Address == "" || len(in.Address) > 4096 {
		return ContactVerificationResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "invalid contact address")
	}

	info, sess, err := a.IntrospectFirstParty(ctx, in.Token)
	if err != nil {
		return ContactVerificationResult{}, err
	}

	if err := a.checkStepUp(ctx, sess, ActionAddContact); err != nil {
		return ContactVerificationResult{}, err
	}

	req, err := c.send(ctx, info, in.Address, sess.ClientID)
	if errors.Is(err, reset.ErrUnavailable) {
		return ContactVerificationResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "contact address cannot be verified")
	}

	if err != nil {
		return ContactVerificationResult{}, NewOAuthErrorFrom(err)
	}

	return ContactVerificationResult{Request: req.ID, Interaction: reset.MethodInteraction(c.method), Data: req.Data}, nil
}

// ListContacts returns the caller's contacts by channel.
func (a *Auth) ListContacts(ctx context.Context, tok string) (map[string][]Contact, error) {
	info, _, err := a.IntrospectFirstParty(ctx, tok)
	if err != nil {
		return nil, err
	}

	return info.Contacts, nil
}

// contactManager resolves the ContactManager and the active session behind token, which must meet
// the step-up policy for action.
func (a *Auth) contactManager(ctx context.Context, tok, action string) (ContactManager, UserInfo, *session.Session, error) {
	manager, ok := a.users.(ContactManager)
	if !ok {
		return nil, UserInfo{}, nil, NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "contact management is not enabled")
	}

	info, sess, err := a.IntrospectFirstParty(ctx, tok)
	if err != nil {
		return nil, UserInfo{}, nil, err
	}

	if err := a.checkStepUp(ctx, sess, action); err != nil {
		return nil, UserInfo{}, nil, err
	}

	return manager, info, sess, nil
}

// SetPrimaryContact makes an address the caller's primary one on its channel.
func (a *Auth) SetPrimaryContact(ctx context.Context, in ContactRequest) error {
	manager, info, sess, err := a.contactManager(ctx, in.Token, ActionPrimaryContact)
	if err != nil {
		return err
	}

	in.Address = a.NormalizeAddress(in.Channel, in.Address)

	if err := manager.SetPrimaryContact(ctx, info.ID, in.Channel, in.Address); err != nil {
		return NewOAuthErrorFrom(err)
	}

	a.emit(ctx, event.Event{Type: event.TypeContactPrimary, UserID: info.ID, ClientID: sess.ClientID, IP: in.IP, Detail: map[string]any{"channel": in.Channel, "address": in.Address}})

	return nil
}

// CancelContactVerification cancels the pending verification of address on channel for user.
func (a *Auth) CancelContactVerification(ctx context.Context, userID, channel, address string) error {
	if a.verifications == nil {
		return nil
	}

	pending, err := a.verifications.Open(ctx, channel, userID, a.NormalizeAddress(channel, address))
	if errors.Is(err, contact.ErrNotFound) {
		return nil
	}

	if err != nil {
		return err
	}

	if _, err := a.verifications.Consume(ctx, pending.ID); err != nil && !errors.Is(err, contact.ErrNotFound) {
		return err
	}

	return nil
}

// RemoveContact removes an address from the caller's account and cancels its pending
// verification.
func (a *Auth) RemoveContact(ctx context.Context, in ContactRequest) error {
	manager, info, sess, err := a.contactManager(ctx, in.Token, ActionRemoveContact)
	if err != nil {
		return err
	}

	in.Address = a.NormalizeAddress(in.Channel, in.Address)

	if err := a.CancelContactVerification(ctx, info.ID, in.Channel, in.Address); err != nil {
		return NewOAuthErrorFrom(err)
	}

	if err := manager.RemoveContact(ctx, info.ID, in.Channel, in.Address); err != nil {
		return NewOAuthErrorFrom(err)
	}

	a.emit(ctx, event.Event{Type: event.TypeContactRemoved, UserID: info.ID, ClientID: sess.ClientID, IP: in.IP, Detail: map[string]any{"channel": in.Channel, "address": in.Address}})

	return nil
}
