// Package push is an example asynchronous (out-of-band approval) MFA driver: the login waits on
// GET /mfa/status while an approval arrives via a device call or the vendor webhook.
//
// It keeps challenges in process memory and stands in for vendor delivery with a log line naming
// the challenge to approve. Wire a real vendor into a copy of it. Import it for its side effect
// of registering the "push" driver:
//
//	import _ "example/portal/push"
package push

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"azugo.io/auth/contract"
	"azugo.io/auth/mfa"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// DriverName is the registered driver name.
const DriverName = "push"

// HeaderCallbackSecret carries the shared secret authenticating the vendor webhook.
const HeaderCallbackSecret = "X-Callback-Secret" //nolint:gosec

// challengeTTL bounds how long an unanswered challenge is remembered.
const challengeTTL = 10 * time.Minute

func init() {
	mfa.Register(DriverName, driver{})
}

type driver struct{}

// Open creates the push method. Config keys: callback_secret (required for the webhook to be
// accepted; without it every callback is rejected).
func (driver) Open(store mfa.Store, cfg *contract.MFAMethodConfig) (mfa.Method, error) {
	return &method{
		store:      store,
		name:       cfg.Name,
		secret:     cfg.Config["callback_secret"],
		challenges: make(map[string]*challenge),
	}, nil
}

type challenge struct {
	userID string
	// code is the six-digit number the user compares with, or enters on, the device.
	code   string
	result mfa.VerifyResult
	// enrollment is the device that answered, when the vendor reported it.
	enrollment string
	created    time.Time
}

type method struct {
	store  mfa.Store
	name   string
	secret string

	mu         sync.Mutex
	challenges map[string]*challenge
}

// BeginEnroll asks the client for the device identifier the vendor would push to.
func (m *method) BeginEnroll(context.Context, string, contract.UserInfo) (mfa.EnrollmentData, error) {
	return mfa.EnrollmentData{Data: map[string]any{"required": []string{"device"}}}, nil
}

// FinishEnroll keeps the device identifier as the enrollment secret.
func (m *method) FinishEnroll(_ context.Context, _ string, _ []byte, response map[string]any) ([]byte, error) {
	device, _ := response["device"].(string)
	if device == "" {
		return nil, mfa.ErrInvalidResponse
	}

	return []byte(device), nil
}

// BeginVerify opens a pending challenge, delivered to every enrolled device, and returns the
// transaction code for the client to display, so the user can match it against the one the
// device shows.
func (m *method) BeginVerify(ctx context.Context, userID string) (string, map[string]any, error) {
	devices, err := mfa.Enrolled(ctx, m.store, userID, m.name)
	if err != nil {
		return "", nil, err
	}

	if len(devices) == 0 {
		return "", nil, mfa.ErrNotEnrolled
	}

	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, err
	}

	id := base64.RawURLEncoding.EncodeToString(buf)

	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", nil, err
	}

	code := fmt.Sprintf("%06d", n)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.prune()
	m.challenges[id] = &challenge{userID: userID, code: code, result: mfa.VerifyPending, created: time.Now()}

	for _, d := range devices {
		slog.Info("push challenge issued; approve it via the webhook", "user", userID, "device", string(d.Secret), "label", d.Label, "challenge_id", id, "transaction", code)
	}

	return id, map[string]any{"transaction": code}, nil
}

// Verify reports the challenge state. The login client can only poll: approval arrives
// out-of-band through HandleCallback or Approve, never through the response it submits.
func (m *method) Verify(_ context.Context, userID, challengeID string, _ map[string]any) (mfa.Verification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.prune()

	c, ok := m.challenges[challengeID]
	if !ok || c.userID != userID {
		return mfa.Verification{Result: mfa.VerifyDenied}, nil
	}

	if c.result != mfa.VerifyPending {
		delete(m.challenges, challengeID)
	}

	return mfa.Verification{Result: c.result, EnrollmentID: c.enrollment}, nil
}

// settle records the out-of-band decision for a pending challenge; callers hold mu.
func (c *challenge) settle(approved bool, enrollment string) {
	if c.result != mfa.VerifyPending {
		return
	}

	c.enrollment = enrollment

	c.result = mfa.VerifyDenied
	if approved {
		c.result = mfa.VerifyApproved
	}
}

// Approve settles userID's newest pending challenge on m, standing in for the device or
// vendor in development and tests. It reports whether a pending challenge was found.
func Approve(m mfa.Method, userID string, approved bool) bool {
	pm, ok := m.(*method)
	if !ok {
		return false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.prune()

	var newest *challenge

	for _, c := range pm.challenges {
		if c.userID == userID && c.result == mfa.VerifyPending && (newest == nil || c.created.After(newest.created)) {
			newest = c
		}
	}

	if newest == nil {
		return false
	}

	newest.settle(approved, "")

	return true
}

// Async marks the factor as verified out-of-band.
func (m *method) Async() bool {
	return true
}

// HandleCallback settles a challenge from the vendor webhook body
// {"challenge_id":"...","approved":true,"device":"..."}; device is optional.
func (m *method) HandleCallback(ctx *azugo.Context) error {
	if m.secret == "" || subtle.ConstantTimeCompare([]byte(ctx.Header.Get(HeaderCallbackSecret)), []byte(m.secret)) != 1 {
		return callbackError{status: http.StatusForbidden, msg: "invalid callback secret"}
	}

	var body struct {
		ChallengeID string `json:"challenge_id"`
		Approved    bool   `json:"approved"`
		// Device is the identifier of the device that answered, when the vendor reports it.
		Device string `json:"device"`
	}

	if err := ctx.Body.JSON(&body); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.prune()

	c, ok := m.challenges[body.ChallengeID]
	if !ok {
		return callbackError{status: http.StatusNotFound, msg: "unknown challenge"}
	}

	c.settle(body.Approved, m.enrollmentOf(ctx, c.userID, body.Device))

	return nil
}

// enrollmentOf resolves the device identifier the webhook names to the enrollment id.
func (m *method) enrollmentOf(ctx context.Context, userID, device string) string {
	if device == "" {
		return ""
	}

	enrolled, err := mfa.Enrolled(ctx, m.store, userID, m.name)
	if err != nil {
		return ""
	}

	for _, e := range enrolled {
		if string(e.Secret) == device {
			return e.ID
		}
	}

	return ""
}

// callbackError is a webhook rejection carrying its HTTP status.
type callbackError struct {
	status int
	msg    string
}

func (e callbackError) Error() string {
	return e.msg
}

// StatusCode implements http.ResponseStatusCode.
func (e callbackError) StatusCode() int {
	return e.status
}

// SafeError implements azugo.SafeError.
func (e callbackError) SafeError() string {
	return e.msg
}

// prune drops stale challenges; callers hold mu.
func (m *method) prune() {
	cutoff := time.Now().Add(-challengeTTL)

	for id, c := range m.challenges {
		if c.created.Before(cutoff) {
			delete(m.challenges, id)
		}
	}
}

var _ interface {
	mfa.Method
	mfa.AsyncMethod
	mfa.CallbackHandler
} = (*method)(nil)
