package mfa

import (
	"context"
	"errors"
	"testing"
	"time"

	"azugo.io/auth/contract"

	"github.com/go-quicktest/qt"
)

type fakeMethod struct{ name string }

func (fakeMethod) BeginEnroll(context.Context, string, contract.UserInfo) (EnrollmentData, error) {
	return EnrollmentData{}, nil
}
func (fakeMethod) FinishEnroll(context.Context, string, []byte, map[string]any) ([]byte, error) {
	return nil, nil
}
func (fakeMethod) BeginVerify(context.Context, string) (string, map[string]any, error) {
	return "", nil, nil
}
func (fakeMethod) Verify(context.Context, string, string, map[string]any) (Verification, error) {
	return Verification{Result: VerifyApproved}, nil
}

type fakeDriver struct{ fail bool }

func (d fakeDriver) Open(_ Store, cfg *contract.MFAMethodConfig) (Method, error) {
	if d.fail || cfg.Config["fail"] == "yes" {
		return nil, errors.New("boom")
	}

	return fakeMethod{name: cfg.Name}, nil
}

func init() {
	Register("fake", fakeDriver{})
	Register("broken", fakeDriver{fail: true})
}

func TestRegistryResolvesConfiguredAndZeroConfigDrivers(t *testing.T) {
	cfg := &contract.Configuration{MFAMethods: []contract.MFAMethodConfig{
		{Name: "app", Driver: "fake", Config: map[string]string{"k": "v"}},
	}}
	r := NewConfigRegistry(cfg, NewMemoryStore())

	names, err := r.Names(context.Background())
	qt.Assert(t, qt.IsNil(err))
	// "fake" is referenced by an entry, so it is not auto-available under its own name;
	// "broken" fails to open and is dropped.
	qt.Check(t, qt.DeepEquals(names, []string{"app"}))

	m, err := r.Get(context.Background(), "app")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(m.(fakeMethod).name, "app"))

	_, err = r.Get(context.Background(), "fake")
	qt.Check(t, qt.ErrorIs(err, ErrUnknownMethod))

	_, err = r.Get(context.Background(), "nope")
	qt.Check(t, qt.ErrorIs(err, ErrUnknownMethod))

	// Dropping the entry makes the bare driver available again, and a config change re-opens.
	cfg.MFAMethods = nil

	names, err = r.Names(context.Background())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(names, []string{"fake"}))

	cfg.MFAMethods = []contract.MFAMethodConfig{{Driver: "fake", Config: map[string]string{"fail": "yes"}}}

	_, err = r.Get(context.Background(), "fake")
	qt.Check(t, qt.IsNotNil(err))
}

func TestMemoryStore(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	list, err := s.List(ctx, "u1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(list, 0))

	qt.Assert(t, qt.IsNil(s.Enroll(ctx, &Enrollment{ID: "e1", UserID: "u1", Method: "totp", Label: "phone", Secret: []byte("a")})))
	qt.Assert(t, qt.IsNil(s.Enroll(ctx, &Enrollment{ID: "e2", UserID: "u1", Method: "push", Secret: []byte("b")})))
	qt.Assert(t, qt.IsNil(s.Enroll(ctx, &Enrollment{ID: "e3", UserID: "u1", Method: "totp", Label: "tablet", Secret: []byte("c")})))
	// Same ID replaces.
	qt.Assert(t, qt.IsNil(s.Enroll(ctx, &Enrollment{ID: "e1", UserID: "u1", Method: "totp", Label: "phone", Secret: []byte("a2")})))

	swapped, err := s.CompareAndSwap(ctx, "u1", "e3", []byte("c"), []byte("d"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(swapped))

	swapped, err = s.CompareAndSwap(ctx, "u1", "e3", []byte("c"), []byte("e"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(swapped))

	methods, err := EnrolledMethods(ctx, s, "u1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(methods, []string{"totp", "push"}))

	totps, err := Enrolled(ctx, s, "u1", "totp")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(totps, 2))
	qt.Check(t, qt.Equals(string(totps[0].Secret), "a2"))
	qt.Check(t, qt.Equals(totps[1].Label, "tablet"))
	qt.Check(t, qt.Equals(string(totps[1].Secret), "d"))

	// Listed enrollments are copies.
	totps[0].Secret[0] = 'x'

	totps, err = Enrolled(ctx, s, "u1", "totp")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(totps[0].Secret), "a2"))

	at := time.Now()
	qt.Assert(t, qt.IsNil(s.Touch(ctx, "u1", "e3", at)))
	qt.Check(t, qt.ErrorIs(s.Touch(ctx, "u1", "nope", at), ErrNotEnrolled))

	totps, err = Enrolled(ctx, s, "u1", "totp")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNil(totps[0].LastUsedAt))
	qt.Check(t, qt.IsTrue(totps[1].LastUsedAt.Equal(at)))

	qt.Assert(t, qt.IsNil(s.Revoke(ctx, "u1", "e1")))
	qt.Check(t, qt.ErrorIs(s.Revoke(ctx, "u1", "e1"), ErrNotEnrolled))
	qt.Check(t, qt.ErrorIs(s.Revoke(ctx, "u2", "e2"), ErrNotEnrolled))

	methods, err = EnrolledMethods(ctx, s, "u1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(methods, []string{"push", "totp"}))
}

func TestMethodHelpers(t *testing.T) {
	qt.Check(t, qt.DeepEquals(MethodAMR(fakeMethod{}), []string{"mfa"}))
	qt.Check(t, qt.Equals(MethodInteraction(fakeMethod{}), InteractionCode))
}
