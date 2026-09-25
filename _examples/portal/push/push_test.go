package push

import (
	"context"
	"testing"
	"time"

	"azugo.io/auth/contract"
	"azugo.io/auth/mfa"

	"github.com/go-quicktest/qt"
)

func TestChallengeLifecycle(t *testing.T) {
	store := mfa.NewMemoryStore()

	_, err := driver{}.Open(store, &contract.MFAMethodConfig{Name: "push", Driver: "push"})
	qt.Check(t, qt.IsNotNil(err))

	m, err := driver{}.Open(store, &contract.MFAMethodConfig{Name: "push", Driver: "push", Config: map[string]string{"callback_secret": "s"}})
	qt.Assert(t, qt.IsNil(err))

	ctx := context.Background()

	_, err = m.FinishEnroll(ctx, "u1", nil, nil)
	qt.Check(t, qt.ErrorIs(err, mfa.ErrInvalidResponse))

	device, err := m.FinishEnroll(ctx, "u1", nil, map[string]any{"device": "phone"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(store.Enroll(ctx, &mfa.Enrollment{ID: "e1", UserID: "u1", Method: "push", Label: "Phone", Secret: device})))

	_, _, err = m.BeginVerify(ctx, "u2")
	qt.Check(t, qt.ErrorIs(err, mfa.ErrNotEnrolled))

	id, data, err := m.BeginVerify(ctx, "u1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(id != ""))
	qt.Check(t, qt.IsTrue(data["transaction"] != ""))

	res, err := m.Verify(ctx, "u1", id, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Result, mfa.VerifyPending))

	// Another user's poll of the same challenge is denied.
	res, err = m.Verify(ctx, "u2", id, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Result, mfa.VerifyDenied))

	// The login client cannot approve its own challenge through the response it submits.
	res, err = m.Verify(ctx, "u1", id, map[string]any{"approved": true})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Result, mfa.VerifyPending))

	qt.Check(t, qt.IsFalse(Approve(m, "u2", true)))
	qt.Check(t, qt.IsTrue(Approve(m, "u1", false)))

	res, err = m.Verify(ctx, "u1", id, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Result, mfa.VerifyDenied))

	// Settled challenges are forgotten.
	res, err = m.Verify(ctx, "u1", id, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Result, mfa.VerifyDenied))

	// Expired challenges are rejected and cannot be settled through the development helper.
	expired, _, err := m.BeginVerify(ctx, "u1")
	qt.Assert(t, qt.IsNil(err))

	pm := m.(*method)
	pm.mu.Lock()
	pm.challenges[expired].created = time.Now().Add(-challengeTTL)
	pm.mu.Unlock()

	res, err = m.Verify(ctx, "u1", expired, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Result, mfa.VerifyDenied))

	expired, _, err = m.BeginVerify(ctx, "u1")
	qt.Assert(t, qt.IsNil(err))

	pm.mu.Lock()
	pm.challenges[expired].created = time.Now().Add(-challengeTTL)
	pm.mu.Unlock()

	qt.Check(t, qt.IsFalse(Approve(m, "u1", true)))

	qt.Check(t, qt.Equals(mfa.MethodInteraction(m), mfa.InteractionPoll))
}
