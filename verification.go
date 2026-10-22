package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"azugo.io/auth/contact"
	"azugo.io/auth/contract"
	"azugo.io/auth/event"
	"azugo.io/auth/reset"
	"azugo.io/auth/session"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"github.com/goccy/go-json"
	"go.uber.org/zap"
)

// Well-known contact channels.
const (
	ChannelEmail = contract.ChannelEmail
	ChannelPhone = contract.ChannelPhone
)

// AddressNormalizer canonicalizes a contact address, so spelling variants of one address
// compare equal.
type AddressNormalizer interface {
	Normalize(channel, address string) string
}

// AddressNormalizerFunc adapts a plain function to the AddressNormalizer interface.
type AddressNormalizerFunc func(channel, address string) string

// Normalize implements AddressNormalizer.
func (f AddressNormalizerFunc) Normalize(channel, address string) string {
	return f(channel, address)
}

// DefaultAddressNormalizer trims every address, lowercases an email and strips the spaces and
// separators of a phone number, keeping its leading "+".
var DefaultAddressNormalizer AddressNormalizer = AddressNormalizerFunc(func(channel, address string) string {
	address = strings.TrimSpace(address)

	switch channel {
	case ChannelEmail:
		return strings.ToLower(address)
	case ChannelPhone:
		return strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) || strings.ContainsRune("-.()", r) {
				return -1
			}

			return r
		}, address)
	default:
		return address
	}
})

// AddressNormalization replaces DefaultAddressNormalizer.
func AddressNormalization(n AddressNormalizer) Option {
	return func(a *Auth) { a.addresses = n }
}

// NormalizeAddress returns the canonical form of address on channel, the form the library hands
// to the user provider.
func (a *Auth) NormalizeAddress(channel, address string) string {
	return a.addresses.Normalize(channel, address)
}

// ContactVerification enables the built-in verify_<channel> login step: an account that holds
// addresses on channel but none verified is held at a pending_step, ahead of MFA, until it
// presents the secret method delivers, and a registration giving an address on channel answers
// uniformly. The user provider must be a ContactVerifier.
func ContactVerification(channel string, method reset.Method) Option {
	return func(a *Auth) {
		a.contacts = append(a.contacts, &contactStep{auth: a, channel: channel, method: method})
	}
}

// ContactVerificationRequest carries the proof delivered for a contact verification request.
type ContactVerificationRequest struct {
	// Request is the verification request ID the delivered link or code page carries.
	Request string
	// Response is the method-specific proof, e.g. {"code":"123456"} or {"token":"..."}.
	Response map[string]any
	IP       string
}

// ContactChannels returns the channels with contact verification enabled, in evaluation order.
func (a *Auth) ContactChannels() []string {
	channels := make([]string, 0, len(a.contacts))
	for _, c := range a.contacts {
		channels = append(channels, c.channel)
	}

	return channels
}

// contactStep returns the verification step of channel, or nil.
func (a *Auth) contactStep(channel string) *contactStep {
	for _, c := range a.contacts {
		if c.channel == channel {
			return c
		}
	}

	return nil
}

// VerifyContact verifies the proof delivered for a contact verification request outside of a
// login, e.g. from a mailed link opened in another browser.
func (a *Auth) VerifyContact(ctx context.Context, in ContactVerificationRequest) error {
	if len(a.contacts) == 0 {
		return NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "contact verification is not enabled")
	}

	keys := throttleKeys("", in.IP)

	if err := a.checkThrottle(ctx, keys, "", in.IP); err != nil {
		return err
	}

	invalid := NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "invalid or expired verification request")

	if in.Request == "" {
		a.failThrottle(ctx, keys)

		return invalid
	}

	req, err := a.verifications.Get(ctx, in.Request)
	if err != nil && !errors.Is(err, contact.ErrNotFound) {
		a.refundThrottle(ctx, keys)

		return NewOAuthErrorFrom(err)
	}

	var c *contactStep
	if req != nil {
		c = a.contactStep(strings.TrimPrefix(req.Method, "verify_"))
	}

	// An unknown request, such as the decoy a repeated registration gets, is guessed at under its
	// own limit and answered like a wrong proof.
	if c == nil {
		decoy := []string{fmt.Sprintf("verify-request:%x", sha256.Sum256([]byte(in.Request)))}

		if err := a.checkThrottle(ctx, decoy, "", in.IP); err != nil {
			a.refundThrottle(ctx, keys)

			return err
		}

		a.failThrottle(ctx, append(keys, decoy...))

		return invalid
	}

	// Guesses count against the address, whichever request or login presents them.
	guess := c.addressKey(req.UserID, req.Identifier)

	if err := a.checkThrottle(ctx, []string{guess}, req.ClientID, in.IP); err != nil {
		a.refundThrottle(ctx, keys)

		return err
	}

	keys = append(keys, guess)

	info, err := a.users.GetUser(ctx, req.UserID)
	if err != nil {
		a.refundThrottle(ctx, keys)

		return NewOAuthErrorFrom(err)
	}

	v, err := c.method.Verify(ctx, req, info, in.Response)
	if err != nil {
		a.refundThrottle(ctx, keys)

		return NewOAuthErrorFrom(err)
	}

	if v == reset.VerifyPending {
		a.refundThrottle(ctx, keys)

		return NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "contact verification is awaiting approval")
	}

	// Anything but an approval is refused.
	if v != reset.VerifyApproved {
		a.failThrottle(ctx, keys)

		return invalid
	}

	a.passThrottle(ctx, keys, guess)

	return c.complete(ctx, req, in.IP)
}

// contactStep is the built-in verify_<channel> login step.
type contactStep struct {
	auth    *Auth
	channel string
	method  reset.Method
}

// addressKey identifies userID's address on the channel in the guess, resend and delivery limits.
func (c *contactStep) addressKey(userID, address string) string {
	return fmt.Sprintf("verify:%s:%s:%x", c.channel, userID, sha256.Sum256([]byte(c.auth.NormalizeAddress(c.channel, address))))
}

func (c *contactStep) Name() string {
	return "verify_" + c.channel
}

// pending returns the address to verify while the channel holds addresses and none is verified.
func (c *contactStep) pending(info UserInfo) (string, bool) {
	var address string

	for _, ct := range info.Contacts[c.channel] {
		if ct.Verified {
			return "", false
		}

		if address == "" || ct.Primary {
			address = ct.Address
		}
	}

	return address, address != ""
}

// live returns the open verification request of userID for address, or nil.
func (c *contactStep) live(ctx context.Context, userID, address string) (*reset.Request, error) {
	req, err := c.auth.verifications.Open(ctx, c.channel, userID, c.auth.NormalizeAddress(c.channel, address))
	if errors.Is(err, contact.ErrNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	if req.Method != c.Name() {
		return nil, nil
	}

	return req, nil
}

// send delivers a fresh secret for address under the user's resend cooldown and cap on the
// address and the user's send cap on the channel.
func (c *contactStep) send(ctx context.Context, info UserInfo, address, clientID string) (*reset.Request, error) {
	a := c.auth
	flow := c.addressKey(info.ID, address)
	budget := "verify-open:" + c.channel + ":" + info.ID
	sent := c.channel + ":" + info.ID

	// One user must not message many addresses
	ok, retryAfter, err := a.sends.Allow(ctx, sent)
	if err != nil {
		return nil, err
	}

	if !ok {
		a.emit(ctx, event.Event{Type: event.TypeLockout, UserID: info.ID, ClientID: clientID, Detail: map[string]any{"key": "contact-send", "channel": c.channel}})

		return nil, NewThrottledError(retryAfter)
	}

	release, err := a.limitChallenge(ctx, flow, budget, a.config.ContactVerificationTTL, clientID, c.Name())
	if err != nil {
		_ = a.sends.Refund(ctx, sent)

		return nil, err
	}

	req, err := c.open(ctx, info, address, clientID)
	if err != nil {
		release()

		_ = a.sends.Refund(ctx, sent)

		return nil, err
	}

	a.failThrottle(ctx, []string{budget})

	return req, nil
}

// open delivers a fresh verification secret for address, replacing any request still open for
// the user on the channel and address.
func (c *contactStep) open(ctx context.Context, info UserInfo, address, clientID string) (*reset.Request, error) {
	a := c.auth

	id, err := newJTI()
	if err != nil {
		return nil, err
	}

	address = a.NormalizeAddress(c.channel, address)

	// Only the address being verified may be delivered to
	info.Contacts = map[string][]Contact{c.channel: {{Address: address}}}

	// One account must not flood an address
	delivery := c.addressKey(info.ID, address)

	ok, retryAfter, err := a.deliveries.Allow(ctx, delivery)
	if err != nil {
		return nil, err
	}

	if !ok {
		a.emit(ctx, event.Event{Type: event.TypeLockout, UserID: info.ID, ClientID: clientID, Detail: map[string]any{"key": "contact-delivery", "channel": c.channel}})

		return nil, NewThrottledError(retryAfter)
	}

	now := time.Now()
	ttl := a.config.ContactVerificationTTL
	req := &reset.Request{ID: id, UserID: info.ID, Identifier: address, ClientID: clientID, Method: c.Name(), CreatedAt: now, ExpiresAt: now.Add(ttl)}

	if req.ChallengeID, req.Data, err = c.method.Begin(ctx, req, info); err != nil {
		_ = a.deliveries.Refund(ctx, delivery)

		return nil, err
	}

	if err := a.verifications.Save(ctx, c.channel, req); err != nil {
		return nil, err
	}

	return req, nil
}

// complete consumes request and records its address as verified.
func (c *contactStep) complete(ctx context.Context, req *reset.Request, ip string) error {
	a := c.auth

	// Consume is the single-use guarantee.
	if _, err := a.verifications.Consume(ctx, req.ID); err != nil {
		if errors.Is(err, contact.ErrNotFound) {
			return NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "invalid or expired verification request")
		}

		return NewOAuthErrorFrom(err)
	}

	verifier, _ := a.users.(ContactVerifier)

	err := verifier.VerifyContact(ctx, req.UserID, c.channel, req.Identifier)

	// Another account proved the address first.
	if errors.Is(err, ErrUserAlreadyExists) {
		return NewOAuthError(http.StatusConflict, ErrCodeInvalidRequest, "contact address is already in use")
	}

	if err != nil {
		// The proof stays usable for a retry unless a newer request has replaced it.
		if _, lerr := a.verifications.Open(ctx, c.channel, req.UserID, req.Identifier); errors.Is(lerr, contact.ErrNotFound) {
			if serr := a.verifications.Save(ctx, c.channel, req); serr != nil {
				a.Log(ctx).Error("failed to restore contact verification request", zap.String("user.id", req.UserID), zap.String("channel", c.channel), zap.Error(serr))
			}
		}

		return NewOAuthErrorFrom(err)
	}

	a.emit(ctx, event.Event{Type: event.TypeContactVerified, UserID: req.UserID, ClientID: req.ClientID, IP: ip, Detail: map[string]any{"channel": c.channel, "address": req.Identifier}})

	return nil
}

func (c *contactStep) Required(_ context.Context, _ *session.Session, info UserInfo) (bool, error) {
	_, required := c.pending(info)

	return required, nil
}

// Prompt delivers a secret unless one is still open for the address.
func (c *contactStep) Prompt(ctx context.Context, sess *session.Session, info UserInfo) (StepPrompt, error) {
	address, ok := c.pending(info)
	if !ok {
		return StepPrompt{Interaction: reset.MethodInteraction(c.method)}, nil
	}

	req, err := c.live(ctx, info.ID, address)
	if err != nil {
		return StepPrompt{}, err
	}

	if req == nil {
		if req, err = c.open(ctx, info, address, sess.ClientID); err != nil {
			// A throttled address still parks the login at the step, to resend later.
			if oe, ok := errors.AsType[*OAuthError](err); ok && oe.Code == ErrCodeSlowDown {
				return StepPrompt{Interaction: reset.MethodInteraction(c.method), Data: map[string]any{"error": "delivery_throttled", "retry_after": int(oe.RetryAfter.Seconds() + 0.999)}}, nil
			}

			return StepPrompt{}, err
		}
	}

	return StepPrompt{Interaction: reset.MethodInteraction(c.method), Data: req.Data}, nil
}

// Resolve verifies the delivered secret, or re-sends it when the payload asks for "resend".
func (c *contactStep) Resolve(ctx context.Context, sess *session.Session, info UserInfo, payload []byte) (StepResult, error) {
	response := make(map[string]any)

	if trimmed := bytes.TrimSpace(payload); len(trimmed) > 0 && trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &response); err != nil {
			return StepResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "invalid step payload")
		}
	} else if form, err := url.ParseQuery(string(trimmed)); err == nil {
		for k := range form {
			response[k] = form.Get(k)
		}
	}

	// Verified meanwhile, e.g. through the link in another browser.
	address, ok := c.pending(info)
	if !ok {
		return StepResult{Done: true}, nil
	}

	// A resend delivers a new secret under the user's resend cooldown and cap.
	if resend, _ := response["resend"].(bool); resend || response["resend"] == "true" {
		if _, err := c.send(ctx, info, address, sess.ClientID); err != nil {
			if _, ok := errors.AsType[*OAuthError](err); !ok {
				c.auth.Log(ctx).Error("failed to resend contact verification", zap.String("user.id", info.ID), zap.String("channel", c.channel), zap.Error(err))
			}

			return StepResult{}, err
		}

		return StepResult{Data: map[string]any{"resent": true}, NoAttempt: true}, nil
	}

	req, err := c.live(ctx, info.ID, address)
	if err != nil {
		return StepResult{}, err
	}

	// An expired request is replaced by the prompt that follows.
	if req == nil {
		return StepResult{Data: map[string]any{"error": "expired"}, NoAttempt: true}, nil
	}

	guess := []string{c.addressKey(req.UserID, req.Identifier)}

	if err := c.auth.checkThrottle(ctx, guess, sess.ClientID, ""); err != nil {
		return StepResult{}, err
	}

	v, err := c.method.Verify(ctx, req, info, response)
	if err != nil {
		c.auth.refundThrottle(ctx, guess)

		return StepResult{}, err
	}

	// Polling an outstanding approval is no guess.
	if v == reset.VerifyPending {
		c.auth.refundThrottle(ctx, guess)

		return StepResult{Data: map[string]any{"pending": true}, NoAttempt: true}, nil
	}

	if v != reset.VerifyApproved {
		c.auth.failThrottle(ctx, guess)

		return StepResult{Data: map[string]any{"error": "invalid_response"}}, nil
	}

	c.auth.resetThrottle(ctx, guess)

	var ip string
	if actx := azugo.RequestContext(ctx); actx != nil {
		ip = actx.IP().String()
	}

	if err := c.complete(ctx, req, ip); err != nil {
		return StepResult{}, err
	}

	return StepResult{Done: true}, nil
}
