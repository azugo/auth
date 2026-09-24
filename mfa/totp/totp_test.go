package totp

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"azugo.io/auth/contract"
	"azugo.io/auth/mfa"

	"github.com/go-quicktest/qt"
)

type concurrentStore struct {
	mfa.Store
	reads   atomic.Int32
	ready   chan struct{}
	release chan struct{}
}

func (s *concurrentStore) List(ctx context.Context, userID string) ([]*mfa.Enrollment, error) {
	list, err := s.Store.List(ctx, userID)
	if s.reads.Add(1) <= 2 {
		if s.reads.Load() == 2 {
			close(s.ready)
		}

		<-s.release
	}

	return list, err
}

// enroll finishes an enrollment the way the library does: the returned secret is stored under
// a fresh id.
func enroll(t *testing.T, store mfa.Store, m mfa.Method, id string, state []byte, response map[string]any) {
	t.Helper()

	secret, err := m.FinishEnroll(context.Background(), "u1", state, response)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(store.Enroll(context.Background(), &mfa.Enrollment{ID: id, UserID: "u1", Method: "totp", Secret: secret})))
}

func TestEnrollVerifyAndReplay(t *testing.T) {
	store := mfa.NewMemoryStore()

	m, err := driver{}.Open(store, &contract.MFAMethodConfig{Name: "totp", Driver: "totp", Config: map[string]string{"issuer": "Example"}})
	qt.Assert(t, qt.IsNil(err))

	ctx := context.Background()

	data, err := m.BeginEnroll(ctx, "u1", contract.UserInfo{Email: "alice@example.com"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(data.Data["issuer"], "Example"))
	qt.Check(t, qt.Equals(data.Data["account"], "alice@example.com"))
	qt.Check(t, qt.IsTrue(len(data.State) > 0))

	_, err = m.FinishEnroll(ctx, "u1", data.State, map[string]any{"code": "000000"})
	qt.Check(t, qt.ErrorIs(err, mfa.ErrInvalidResponse))

	code, err := GenerateCode(string(data.State), time.Now())
	qt.Assert(t, qt.IsNil(err))
	enroll(t, store, m, "e1", data.State, map[string]any{"code": code})

	// The enrollment code's time step is consumed; the same code is refused on verify.
	res, err := m.Verify(ctx, "u1", "", map[string]any{"code": code})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Result, mfa.VerifyDenied))

	next, err := GenerateCode(string(data.State), time.Now().Add(30*time.Second))
	qt.Assert(t, qt.IsNil(err))

	res, err = m.Verify(ctx, "u1", "", map[string]any{"code": next})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Result, mfa.VerifyApproved))
	qt.Check(t, qt.Equals(res.EnrollmentID, "e1"))

	res, err = m.Verify(ctx, "u1", "", map[string]any{"code": next})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Result, mfa.VerifyDenied))

	qt.Check(t, qt.DeepEquals(mfa.MethodAMR(m), []string{"otp", "mfa"}))

	qt.Assert(t, qt.IsNil(store.Revoke(ctx, "u1", "e1")))

	_, err = m.Verify(ctx, "u1", "", map[string]any{"code": next})
	qt.Check(t, qt.ErrorIs(err, mfa.ErrNotEnrolled))
}

func TestVerifyAcceptsAnyEnrolledDevice(t *testing.T) {
	store := mfa.NewMemoryStore()

	m, err := driver{}.Open(store, &contract.MFAMethodConfig{Name: "totp", Driver: "totp"})
	qt.Assert(t, qt.IsNil(err))

	ctx := context.Background()
	seeds := make([]string, 2)

	for i, id := range []string{"phone", "tablet"} {
		data, err := m.BeginEnroll(ctx, "u1", contract.UserInfo{})
		qt.Assert(t, qt.IsNil(err))

		code, err := GenerateCode(string(data.State), time.Now())
		qt.Assert(t, qt.IsNil(err))
		enroll(t, store, m, id, data.State, map[string]any{"code": code})

		seeds[i] = string(data.State)
	}

	at := time.Now().Add(30 * time.Second)

	for _, seed := range seeds {
		code, err := GenerateCode(seed, at)
		qt.Assert(t, qt.IsNil(err))

		res, err := m.Verify(ctx, "u1", "", map[string]any{"code": code})
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(res.Result, mfa.VerifyApproved))

		// Each device's code is consumed on its own enrollment only.
		res, err = m.Verify(ctx, "u1", "", map[string]any{"code": code})
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(res.Result, mfa.VerifyDenied))
	}
}

func TestVerifyConsumesCodeOnceAcrossConcurrentRequests(t *testing.T) {
	store := &concurrentStore{
		Store:   mfa.NewMemoryStore(),
		ready:   make(chan struct{}),
		release: make(chan struct{}),
	}
	m, err := driver{}.Open(store, &contract.MFAMethodConfig{Name: "totp", Driver: "totp"})
	qt.Assert(t, qt.IsNil(err))

	ctx := context.Background()
	data, err := m.BeginEnroll(ctx, "u1", contract.UserInfo{})
	qt.Assert(t, qt.IsNil(err))

	code, err := GenerateCode(string(data.State), time.Now())
	qt.Assert(t, qt.IsNil(err))
	enroll(t, store, m, "e1", data.State, map[string]any{"code": code})

	code, err = GenerateCode(string(data.State), time.Now().Add(30*time.Second))
	qt.Assert(t, qt.IsNil(err))

	results := make(chan struct {
		result mfa.Verification
		err    error
	}, 2)
	for range 2 {
		go func() {
			result, err := m.Verify(ctx, "u1", "", map[string]any{"code": code})
			results <- struct {
				result mfa.Verification
				err    error
			}{result: result, err: err}
		}()
	}

	<-store.ready
	close(store.release)

	approved := 0
	for range 2 {
		outcome := <-results
		qt.Assert(t, qt.IsNil(outcome.err))
		if outcome.result.Result == mfa.VerifyApproved {
			approved++
		}
	}

	qt.Check(t, qt.Equals(approved, 1))
}

func TestOpenValidatesConfig(t *testing.T) {
	for _, cfg := range []map[string]string{
		{"digits": "7"}, {"period": "0"}, {"algorithm": "MD5"}, {"skew": "x"},
	} {
		_, err := driver{}.Open(mfa.NewMemoryStore(), &contract.MFAMethodConfig{Name: "totp", Driver: "totp", Config: cfg})
		qt.Check(t, qt.IsNotNil(err), qt.Commentf("%v", cfg))
	}

	_, err := driver{}.Open(mfa.NewMemoryStore(), &contract.MFAMethodConfig{Name: "totp", Driver: "totp", Config: map[string]string{
		"digits": "8", "period": "60", "algorithm": "sha256", "skew": "0",
	}})
	qt.Check(t, qt.IsNil(err))
}
