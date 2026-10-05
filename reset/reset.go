// Package reset implements password reset as a choice of verification methods - a mailed
// link, a texted code, an out-of-band approval, a secret question - each proving that the
// caller owns the account before the password is replaced.
package reset

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"azugo.io/auth/contract"

	"azugo.io/core/cache"
)

var (
	// ErrUnknownMethod is returned when no configured or registered method matches the name.
	ErrUnknownMethod = errors.New("unknown reset method")
	// ErrUnavailable is returned by Method.Begin when the account lacks what the method needs,
	// e.g. a phone number.
	ErrUnavailable = errors.New("reset method unavailable for the account")
	// ErrNotFound is returned when no live reset request matches.
	ErrNotFound = errors.New("reset request not found")
)

// Request is the server-side record of a reset in progress. ID is the opaque handle the
// caller holds as reset_token. A decoy for an unknown account has no UserID.
type Request struct {
	ID     string
	UserID string
	// Identifier is the account identifier as presented.
	Identifier string
	ClientID   string
	// Method and ChallengeID identify the open challenge; Data is its prompt, repeated on poll.
	Method      string
	ChallengeID string
	Data        map[string]any
	// Approved is set once an asynchronous method reported approval.
	Approved  bool
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Decoy reports whether the request stands in for an unknown or unservable account.
func (r *Request) Decoy() bool {
	return r.UserID == ""
}

// Store persists reset requests.
type Store interface {
	// Save persists a new request until its ExpiresAt.
	Save(ctx context.Context, r *Request) error
	// Get returns the live request, or ErrNotFound when it is unknown or expired.
	Get(ctx context.Context, id string) (*Request, error)
	// Update persists the current state of an existing request.
	Update(ctx context.Context, r *Request) error
	// Consume atomically fetches and deletes the request. It returns ErrNotFound when the
	// request is unknown, expired or already consumed - the single-use guarantee.
	Consume(ctx context.Context, id string) (*Request, error)
}

// cacheStore is the default Store backed by cache.
type cacheStore struct {
	requests cache.Instance[Request]
}

// NewCacheStore creates the default cache-backed reset Store using the app's cache.
func NewCacheStore(c *cache.Cache) (Store, error) {
	requests, err := cache.Create[Request](c, "auth:pwreset")
	if err != nil {
		return nil, err
	}

	return &cacheStore{requests: requests}, nil
}

// Save persists the request with a TTL equal to its remaining lifetime; an already expired
// request is not stored at all.
func (s *cacheStore) Save(ctx context.Context, r *Request) error {
	ttl := time.Until(r.ExpiresAt)
	if ttl <= 0 {
		return nil
	}

	if err := s.requests.Set(ctx, r.ID, *r, cache.TTL[Request](ttl)); err != nil {
		return err
	}

	return s.requests.Sync(ctx)
}

// Get returns the live request.
func (s *cacheStore) Get(ctx context.Context, id string) (*Request, error) {
	r, err := s.requests.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// A missing key reads as the zero value.
	if r.ID == "" || time.Now().After(r.ExpiresAt) {
		return nil, ErrNotFound
	}

	return &r, nil
}

// Update persists the request, keeping its expiry.
func (s *cacheStore) Update(ctx context.Context, r *Request) error {
	return s.Save(ctx, r)
}

// Consume atomically fetches and deletes the request.
func (s *cacheStore) Consume(ctx context.Context, id string) (*Request, error) {
	r, err := s.requests.Pop(ctx, id)
	if err != nil {
		var knf cache.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil, ErrNotFound
		}

		return nil, err
	}

	if time.Now().After(r.ExpiresAt) {
		return nil, ErrNotFound
	}

	return &r, nil
}

// VerifyResult is the tri-state outcome of Method.Verify.
type VerifyResult string

// VerifyResult values.
const (
	VerifyApproved VerifyResult = "approved" // ownership proven - the password may be replaced
	VerifyDenied   VerifyResult = "denied"   // wrong code / rejected approval - a failed attempt
	VerifyPending  VerifyResult = "pending"  // asynchronous method awaiting out-of-band approval
)

// Interaction hints surfaced to the caller for the selected method.
const (
	InteractionCode = "code" // submit the delivered code with the new password
	InteractionLink = "link" // follow the delivered link, which carries the request and its token
	InteractionPoll = "poll" // wait for an out-of-band approval, then submit the new password
)

// Method is one way for a user to prove ownership of the account being reset.
type Method interface {
	// Begin opens a challenge for the account behind request, e.g. sends a code or a link built
	// from req.ID, or ErrUnavailable when the account lacks what the method needs.
	Begin(ctx context.Context, req *Request, info contract.UserInfo) (challengeID string, data map[string]any, err error)
	// Verify evaluates response against request ChallengeID.
	Verify(ctx context.Context, req *Request, info contract.UserInfo, response map[string]any) (VerifyResult, error)
}

// Interactor is an optional extension declaring its interaction.
type Interactor interface {
	Interaction() string
}

// MethodInteraction returns the caller interaction hint for m.
func MethodInteraction(m Method) string {
	if i, ok := m.(Interactor); ok {
		return i.Interaction()
	}

	return InteractionCode
}

// Deliverer hands a reset secret to the user over the application's channel.
type Deliverer interface {
	// Available reports whether the account has a destination for the channel.
	Available(info contract.UserInfo) bool
	// Deliver sends the secret for request requestID.
	Deliver(ctx context.Context, info contract.UserInfo, requestID, secret string) error
}

// Link returns a method that delivers a single-use 256-bit token.
func Link(d Deliverer) Method {
	return &secretMethod{deliver: d, interaction: InteractionLink, field: "token", generate: func() (string, error) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}

		return base64.RawURLEncoding.EncodeToString(b), nil
	}}
}

// Code returns a method that delivers a numeric code of the given length.
func Code(d Deliverer, digits int) Method {
	limit := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)

	return &secretMethod{deliver: d, interaction: InteractionCode, field: "code", generate: func() (string, error) {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("%0*d", digits, n), nil
	}}
}

// secretMethod delivers a generated secret and keeps only its salted hash as the challenge.
type secretMethod struct {
	deliver     Deliverer
	interaction string
	field       string
	generate    func() (string, error)
}

func (m *secretMethod) Begin(ctx context.Context, req *Request, info contract.UserInfo) (string, map[string]any, error) {
	if !m.deliver.Available(info) {
		return "", nil, ErrUnavailable
	}

	secret, err := m.generate()
	if err != nil {
		return "", nil, err
	}

	// The challenge is live before the secret leaves, and the response does not wait for it.
	go func() {
		_ = m.deliver.Deliver(context.WithoutCancel(ctx), info, req.ID, secret)
	}()

	return hashSecret(req.ID, secret), nil, nil
}

func (m *secretMethod) Verify(_ context.Context, req *Request, _ contract.UserInfo, response map[string]any) (VerifyResult, error) {
	presented, _ := response[m.field].(string)
	if presented == "" || req.ChallengeID == "" {
		return VerifyDenied, nil
	}

	if subtle.ConstantTimeCompare([]byte(hashSecret(req.ID, presented)), []byte(req.ChallengeID)) != 1 {
		return VerifyDenied, nil
	}

	return VerifyApproved, nil
}

func (m *secretMethod) Interaction() string {
	return m.interaction
}

func hashSecret(requestID, secret string) string {
	sum := sha256.Sum256([]byte(requestID + "\x00" + secret))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}
