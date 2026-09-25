// Package mfa defines the multi-factor authentication method drivers, the enrollment Store and
// the registry that resolves configured methods per request.
package mfa

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"azugo.io/auth/contract"

	"azugo.io/azugo"
)

var (
	// ErrUnknownMethod is returned when no configured or registered method matches the name.
	ErrUnknownMethod = errors.New("unknown mfa method")
	// ErrNotEnrolled is returned when the user has no matching enrollment.
	ErrNotEnrolled = errors.New("mfa method not enrolled")
	// ErrInvalidResponse is returned by Method.FinishEnroll for a wrong code or malformed
	// response, counting as a failed attempt.
	ErrInvalidResponse = errors.New("invalid mfa response")
)

// Enrollment is one enrolled instance of a method for a user: an authenticator app, a device
// or a code set. A user may hold several per method.
type Enrollment struct {
	ID     string
	UserID string
	Method string
	// Label is the user-facing name of the device or app.
	Label string
	// Secret is the driver-specific enrollment data; never surfaced to clients.
	Secret     []byte
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// Store persists MFA enrollments.
type Store interface {
	// List returns userID's enrollments, oldest first.
	List(ctx context.Context, userID string) ([]*Enrollment, error)
	// Enroll persists e under its ID, replacing an enrollment with the same ID.
	Enroll(ctx context.Context, e *Enrollment) error
	// CompareAndSwap replaces the secret of userID's enrollment id only when its current value
	// equals expected. It returns false when the enrollment is missing or has changed, allowing
	// one-time factors to be consumed exactly once across concurrent requests.
	CompareAndSwap(ctx context.Context, userID, id string, expected, replacement []byte) (bool, error)
	// Touch records that userID's enrollment id passed verification at at, or ErrNotEnrolled.
	Touch(ctx context.Context, userID, id string, at time.Time) error
	// Revoke removes userID's enrollment id, or ErrNotEnrolled.
	Revoke(ctx context.Context, userID, id string) error
}

// Enrolled returns userID's enrollments in method, oldest first.
func Enrolled(ctx context.Context, s Store, userID, method string) ([]*Enrollment, error) {
	all, err := s.List(ctx, userID)
	if err != nil {
		return nil, err
	}

	return slices.DeleteFunc(all, func(e *Enrollment) bool { return e.Method != method }), nil
}

// EnrolledMethods returns the names of the methods userID is enrolled in, in enrollment order.
func EnrolledMethods(ctx context.Context, s Store, userID string) ([]string, error) {
	all, err := s.List(ctx, userID)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(all))

	for _, e := range all {
		if !slices.Contains(names, e.Method) {
			names = append(names, e.Method)
		}
	}

	return names, nil
}

// VerifyResult is the tri-state outcome of Method.Verify.
type VerifyResult string

// VerifyResult values.
const (
	VerifyApproved VerifyResult = "approved" // factor satisfied - advance the session
	VerifyDenied   VerifyResult = "denied"   // wrong code / rejected push - a failed attempt
	VerifyPending  VerifyResult = "pending"  // async method awaiting out-of-band approval
)

// Verification is the outcome of Method.Verify.
type Verification struct {
	Result VerifyResult
	// EnrollmentID names the enrollment that satisfied the factor, when the method knows it.
	EnrollmentID string
}

// Interaction hints surfaced to the client for the selected method.
const (
	InteractionCode = "code" // submit a code / assertion via POST /mfa/verify
	InteractionPoll = "poll" // wait for out-of-band approval via GET /mfa/status
)

// EnrollmentData is returned by BeginEnroll.
type EnrollmentData struct {
	// Data is surfaced to the client, e.g. {"secret":"...","uri":"otpauth://..."} for TOTP.
	Data map[string]any
	// State is opaque driver state the library hands back to FinishEnroll; never surfaced.
	State []byte
}

// Method encapsulates one authentication factor.
type Method interface {
	// BeginEnroll returns enrollment data for the user.
	BeginEnroll(ctx context.Context, userID string, info contract.UserInfo) (EnrollmentData, error)
	// FinishEnroll verifies the enrollment response against state and returns the secret the
	// library stores; a wrong response returns ErrInvalidResponse.
	FinishEnroll(ctx context.Context, userID string, state []byte, response map[string]any) ([]byte, error)
	// BeginVerify starts a challenge across the user's enrollments. challengeID is the opaque
	// server-side handle; data is surfaced to the client. Both are empty for self-contained
	// methods (TOTP).
	BeginVerify(ctx context.Context, userID string) (challengeID string, data map[string]any, err error)
	// Verify evaluates response against challengeID and the user's enrollments. response is nil
	// when polling an async method.
	Verify(ctx context.Context, userID, challengeID string, response map[string]any) (Verification, error)
}

// ExclusiveMethod is an optional Method extension for factors holding at most one enrollment
// per user.
type ExclusiveMethod interface {
	Exclusive() bool
}

// BackupMethod is an optional Method extension for factors that only back up another one
// (ex. recovery codes).
type BackupMethod interface {
	Backup() bool
}

// AsyncMethod is an optional Method extension for factors verified out-of-band (push
// approval): the login flow signals InteractionPoll instead of prompting for a code.
type AsyncMethod interface {
	Async() bool
}

// CallbackHandler is an optional Method extension for vendors that deliver approval via an
// inbound webhook, dispatched from POST /mfa/callback/{method}. That route is unauthenticated
// and not rate limited.
type CallbackHandler interface {
	HandleCallback(ctx *azugo.Context) error
}

// AMRProvider is an optional Method extension declaring the RFC 8176 amr values recorded when
// the factor passes. Without it "mfa" alone is recorded.
type AMRProvider interface {
	AMR() []string
}

// Driver is implemented by each MFA method package and registered via Register.
type Driver interface {
	// Open creates a Method over the shared store from the configuration entry.
	Open(store Store, cfg *contract.MFAMethodConfig) (Method, error)
}

var (
	driversMu sync.RWMutex
	drivers   = make(map[string]Driver)
)

// Register makes a Driver available under name.
//
// Panics on a nil or duplicate registration.
func Register(name string, d Driver) {
	driversMu.Lock()
	defer driversMu.Unlock()

	if d == nil {
		panic("mfa: Register driver is nil")
	}

	if _, dup := drivers[name]; dup {
		panic("mfa: Register called twice for driver " + name)
	}

	drivers[name] = d
}

func driver(name string) (Driver, error) {
	driversMu.RLock()
	defer driversMu.RUnlock()

	d, ok := drivers[name]
	if !ok {
		return nil, fmt.Errorf("mfa: unknown driver %q", name)
	}

	return d, nil
}

func driverNames() []string {
	driversMu.RLock()
	defer driversMu.RUnlock()

	names := make([]string, 0, len(drivers))
	for name := range drivers {
		names = append(names, name)
	}

	return names
}

// MethodAMR returns the amr values m records when it passes.
func MethodAMR(m Method) []string {
	if p, ok := m.(AMRProvider); ok {
		return p.AMR()
	}

	return []string{"mfa"}
}

// MethodExclusive reports whether m holds at most one enrollment per user.
func MethodExclusive(m Method) bool {
	e, ok := m.(ExclusiveMethod)

	return ok && e.Exclusive()
}

// MethodBackup reports whether m only backs up another factor.
func MethodBackup(m Method) bool {
	b, ok := m.(BackupMethod)

	return ok && b.Backup()
}

// MethodInteraction returns the client interaction hint for m.
func MethodInteraction(m Method) string {
	if a, ok := m.(AsyncMethod); ok && a.Async() {
		return InteractionPoll
	}

	return InteractionCode
}
