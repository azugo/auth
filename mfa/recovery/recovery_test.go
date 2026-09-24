package recovery

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"azugo.io/auth/contract"
	"azugo.io/auth/mfa"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
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

// enroll finishes an enrollment the way the library does: the returned secret is stored.
func enroll(t *testing.T, store mfa.Store, m mfa.Method, state []byte) {
	t.Helper()

	secret, err := m.FinishEnroll(context.Background(), "u1", state, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(store.Enroll(context.Background(), &mfa.Enrollment{ID: "e1", UserID: "u1", Method: "recovery", Secret: secret})))
}

func TestCodesAreSingleUseAndNormalized(t *testing.T) {
	store := mfa.NewMemoryStore()

	m, err := driver{}.Open(store, &contract.MFAMethodConfig{Name: "recovery", Driver: "recovery", Config: map[string]string{"count": "3"}})
	qt.Assert(t, qt.IsNil(err))

	ctx := context.Background()

	data, err := m.BeginEnroll(ctx, "u1", contract.UserInfo{})
	qt.Assert(t, qt.IsNil(err))

	codes, _ := data.Data["codes"].([]string)
	qt.Assert(t, qt.HasLen(codes, 3))
	qt.Check(t, qt.Equals(len(codes[0]), 11)) // 10 characters + separator

	var hashes []string
	qt.Assert(t, qt.IsNil(json.Unmarshal(data.State, &hashes)))
	for _, hash := range hashes {
		qt.Check(t, qt.IsTrue(strings.HasPrefix(hash, "$argon2id$")))
	}

	enroll(t, store, m, data.State)
	qt.Check(t, qt.IsTrue(mfa.MethodExclusive(m)))

	// Case and separators do not matter.
	res, err := m.Verify(ctx, "u1", "", map[string]any{"code": strings.ToUpper(strings.ReplaceAll(codes[0], "-", " "))})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Result, mfa.VerifyApproved))

	res, err = m.Verify(ctx, "u1", "", map[string]any{"code": codes[0]})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Result, mfa.VerifyDenied))

	res, err = m.Verify(ctx, "u1", "", map[string]any{"code": codes[1]})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Result, mfa.VerifyApproved))

	_, err = driver{}.Open(store, &contract.MFAMethodConfig{Name: "recovery", Driver: "recovery", Config: map[string]string{"length": "3"}})
	qt.Check(t, qt.IsNotNil(err))
}

func TestVerifyConsumesCodeOnceAcrossConcurrentRequests(t *testing.T) {
	store := &concurrentStore{
		Store:   mfa.NewMemoryStore(),
		ready:   make(chan struct{}),
		release: make(chan struct{}),
	}
	m, err := driver{}.Open(store, &contract.MFAMethodConfig{Name: "recovery", Driver: "recovery", Config: map[string]string{"count": "1"}})
	qt.Assert(t, qt.IsNil(err))

	ctx := context.Background()
	data, err := m.BeginEnroll(ctx, "u1", contract.UserInfo{})
	qt.Assert(t, qt.IsNil(err))
	codes := data.Data["codes"].([]string)
	enroll(t, store, m, data.State)

	results := make(chan struct {
		result mfa.Verification
		err    error
	}, 2)
	for range 2 {
		go func() {
			result, err := m.Verify(ctx, "u1", "", map[string]any{"code": codes[0]})
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
