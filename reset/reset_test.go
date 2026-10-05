package reset

import (
	"context"
	"errors"
	"testing"
	"time"

	"azugo.io/auth/contract"

	"azugo.io/core/cache"
	"github.com/go-quicktest/qt"
)

func newStore(t *testing.T) Store {
	t.Helper()

	c := cache.New(cache.MemoryCache)
	qt.Assert(t, qt.IsNil(c.Start(context.Background())))
	t.Cleanup(c.Close)

	s, err := NewCacheStore(c)
	qt.Assert(t, qt.IsNil(err))

	return s
}

func TestCacheStoreRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	_, err := s.Get(ctx, "nope")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))

	req := &Request{ID: "r1", UserID: "u1", Method: "email", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	qt.Assert(t, qt.IsNil(s.Save(ctx, req)))

	got, err := s.Get(ctx, "r1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.UserID, "u1"))
	qt.Check(t, qt.IsFalse(got.Decoy()))

	got.Approved = true
	qt.Assert(t, qt.IsNil(s.Update(ctx, got)))

	got, err = s.Consume(ctx, "r1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(got.Approved))

	_, err = s.Consume(ctx, "r1")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))

	_, err = s.Get(ctx, "r1")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))
}

func TestCacheStoreExpired(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(s.Save(ctx, &Request{ID: "r2", UserID: "u1", ExpiresAt: time.Now().Add(-time.Second)})))

	_, err := s.Get(ctx, "r2")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))

	_, err = s.Consume(ctx, "r2")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))
}

// recorder hands each delivered secret to the test.
type recorder struct {
	secrets     chan string
	unavailable bool
}

func newRecorder() *recorder {
	return &recorder{secrets: make(chan string, 8)}
}

func (r *recorder) Available(contract.UserInfo) bool {
	return !r.unavailable
}

func (r *recorder) Deliver(_ context.Context, _ contract.UserInfo, _, secret string) error {
	r.secrets <- secret

	return nil
}

func (r *recorder) secret(t *testing.T) string {
	t.Helper()

	select {
	case s := <-r.secrets:
		return s
	case <-time.After(2 * time.Second):
		t.Fatal("no secret was delivered")

		return ""
	}
}

func TestLinkMethod(t *testing.T) {
	rec := newRecorder()
	m := Link(rec)
	ctx := context.Background()
	req := &Request{ID: "r1"}

	qt.Check(t, qt.Equals(MethodInteraction(m), InteractionLink))

	challenge, data, err := m.Begin(ctx, req, contract.UserInfo{ID: "u1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNil(data))

	secret := rec.secret(t)
	qt.Check(t, qt.IsTrue(challenge != "" && challenge != secret))
	qt.Check(t, qt.HasLen(secret, 43))

	req.ChallengeID = challenge

	v, err := m.Verify(ctx, req, contract.UserInfo{}, map[string]any{"token": secret})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(v, VerifyApproved))

	v, _ = m.Verify(ctx, req, contract.UserInfo{}, map[string]any{"token": "wrong"})
	qt.Check(t, qt.Equals(v, VerifyDenied))

	v, _ = m.Verify(ctx, req, contract.UserInfo{}, nil)
	qt.Check(t, qt.Equals(v, VerifyDenied))

	// The hash is bound to the request, so a secret cannot be moved to another one.
	v, _ = m.Verify(ctx, &Request{ID: "r2", ChallengeID: challenge}, contract.UserInfo{}, map[string]any{"token": secret})
	qt.Check(t, qt.Equals(v, VerifyDenied))

	// An unavailable channel surfaces as such, before anything is generated.
	rec.unavailable = true
	_, _, err = m.Begin(ctx, req, contract.UserInfo{ID: "u1"})
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrUnavailable)))
	qt.Check(t, qt.HasLen(rec.secrets, 0))
}

func TestCodeMethod(t *testing.T) {
	rec := newRecorder()
	m := Code(rec, 6)
	ctx := context.Background()
	req := &Request{ID: "r1"}

	qt.Check(t, qt.Equals(MethodInteraction(m), InteractionCode))

	challenge, _, err := m.Begin(ctx, req, contract.UserInfo{ID: "u1"})
	qt.Assert(t, qt.IsNil(err))

	code := rec.secret(t)
	qt.Assert(t, qt.HasLen(code, 6))

	for _, r := range code {
		qt.Check(t, qt.IsTrue(r >= '0' && r <= '9'))
	}

	req.ChallengeID = challenge

	v, err := m.Verify(ctx, req, contract.UserInfo{}, map[string]any{"code": code})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(v, VerifyApproved))

	// A dead challenge never approves.
	v, _ = m.Verify(ctx, &Request{ID: "r1"}, contract.UserInfo{}, map[string]any{"code": code})
	qt.Check(t, qt.Equals(v, VerifyDenied))
}

func TestStaticRegistry(t *testing.T) {
	r := Methods(map[string]Method{"sms": Code(newRecorder(), 6), "email": Link(newRecorder())})

	names, err := r.Names(context.Background())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(names, []string{"email", "sms"}))

	_, err = r.Get(context.Background(), "email")
	qt.Check(t, qt.IsNil(err))

	_, err = r.Get(context.Background(), "carrier-pigeon")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrUnknownMethod)))
}

type stubDriver struct{}

func (stubDriver) Open(cfg *contract.ResetMethodConfig) (Method, error) {
	return Code(newRecorder(), 4), nil
}

func TestConfigRegistry(t *testing.T) {
	Register("stub", stubDriver{})

	cfg := &contract.Configuration{PasswordResetMethods: []contract.ResetMethodConfig{{Name: "text", Driver: "stub"}}}
	r := NewConfigRegistry(cfg)

	names, err := r.Names(context.Background())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(names, []string{"text"}))

	_, err = r.Get(context.Background(), "text")
	qt.Check(t, qt.IsNil(err))

	// A configured driver is not also offered under its bare name.
	_, err = r.Get(context.Background(), "stub")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrUnknownMethod)))
}
