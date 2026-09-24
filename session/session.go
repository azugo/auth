// Package session defines the server-side session model and the Store interface that
// persists it.
package session

import (
	"context"
	"errors"
	"time"

	"azugo.io/core/paginator"
)

// ErrNotFound is returned when no session matches the given ID.
var ErrNotFound = errors.New("session not found")

// Status is the lifecycle/step state of a session.
type Status string

const (
	// StatusActive is fully authenticated; access tokens may be issued.
	StatusActive Status = "active"
	// StatusPendingPasswordChange requires the user to change their password before
	// the session is promoted to active.
	StatusPendingPasswordChange Status = "pending_password_change"
	// StatusPendingMFASetup requires the user to enrol in an MFA method.
	StatusPendingMFASetup Status = "pending_mfa_setup"
	// StatusPendingMFA requires MFA verification before the session is active.
	StatusPendingMFA Status = "pending_mfa"
	// StatusPendingStep is an application-defined gate that has not yet been satisfied
	// (e.g. tenant/role selection, consent, accepting the portal usage agreement).
	StatusPendingStep Status = "pending_step"
)

// Session is the server-side record for an authenticated (or pending) login.
type Session struct {
	ID        string
	UserID    string
	ClientID  string
	Scope     string
	Status    Status
	Step      string // name of the unresolved login step when Status == pending_step ("" otherwise)
	MFAMethod string // name of the MFA method used to verify (empty until MFA passed)
	// MFAEnrollmentID is the enrollment that satisfied MFA, when the method reported one.
	MFAEnrollmentID string
	// AuthProvider is the external provider name that authenticated this session ("" = local
	// login); used as id_token_hint source for RP-initiated federated logout.
	AuthProvider string
	ACR          string   // satisfied authentication context class (trust level)
	AMR          []string // authentication methods references actually used, e.g. ["pwd","otp"]
	// Context carries application-defined selections bound to the session - the active tenant,
	// the selected role(s), an accepted agreement version, etc.
	Context   map[string]any
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// Valid returns true when the session is still alive, not revoked and not expired.
func (s *Session) Valid() bool {
	return s.RevokedAt == nil && time.Now().Before(s.ExpiresAt)
}

// Active returns true when the session is valid and in the active status.
func (s *Session) Active() bool {
	return s.Valid() && s.Status == StatusActive
}

// Pending returns true when the session is valid but has unresolved steps.
func (s *Session) Pending() bool {
	return s.Valid() && s.Status != StatusActive
}

// Store persists server-side sessions by ID. These are the operations any backend can support,
// including a plain key-value store (e.g. a cache).
type Store interface {
	// Create a new session.
	Create(ctx context.Context, s *Session) error
	// Get session by ID.
	Get(ctx context.Context, id string) (*Session, error)
	// Update persists the current state of an existing session (status, MFA/ACR fields, expiry).
	Update(ctx context.Context, s *Session) error
	// Touch updates session as active (usually by updating LastSeen time).
	Touch(ctx context.Context, id string) error
	// Revoke session and invalidate it.
	Revoke(ctx context.Context, id string) error
}

// Filter narrows which of a user's sessions to return.
type Filter struct {
	// ActiveOnly returns only active sessions.
	ActiveOnly bool
}

// Lister is an optional Store capability for listing of a user's sessions ordered by LastSeen
// descending, narrowed by an optional filter and paging.
type Lister interface {
	// List returns userID's sessions matching filter ordered by LastSeen descending.
	List(ctx context.Context, userID string, filter *Filter, page *paginator.Paginator) (sessions []*Session, pages *paginator.Paginator, err error)
}
