package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/session"
	"azugo.io/auth/throttle"

	"github.com/go-quicktest/qt"
)

func TestLoginLockoutIsPerAccount(t *testing.T) {
	info := UserInfo{ID: "u1", Name: "Alice", Scope: "openid profile"}
	users := fakeUsers{
		users:     map[string]UserInfo{"alice": info, "alice@example.com": info, "carol": {ID: "u2", Scope: "profile"}},
		passwords: map[string]string{"alice": "secret123", "alice@example.com": "secret123", "carol": "secret123"},
	}

	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a, err := New(newApp(t), cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(mfaClient(client.MFAPolicyDisabled)))
	qt.Assert(t, qt.IsNil(err))

	ctx := context.Background()
	login := func(username, password string) error {
		_, err := a.Login(ctx, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: username, Password: password})
		return err
	}

	// Every name of an account spends one budget.
	qt.Check(t, qt.Equals(oauthErrorCode(t, login("alice", "wrong")), ErrCodeInvalidGrant))
	qt.Check(t, qt.Equals(oauthErrorCode(t, login("alice@example.com", "wrong")), ErrCodeInvalidGrant))
	qt.Check(t, qt.Equals(oauthErrorCode(t, login("alice", "secret123")), ErrCodeSlowDown))
	qt.Check(t, qt.IsNil(login("carol", "secret123")))

	// An unknown name is locked out like an account, so the lockout reveals nothing.
	for range 2 {
		qt.Check(t, qt.Equals(oauthErrorCode(t, login("nobody", "wrong")), ErrCodeInvalidGrant))
	}

	qt.Check(t, qt.Equals(oauthErrorCode(t, login("nobody", "wrong")), ErrCodeSlowDown))

	qt.Assert(t, qt.IsNil(a.UnlockLogin(ctx, "u1")))
	qt.Check(t, qt.IsNil(login("alice@example.com", "secret123")))
}

type failingResetThrottle struct {
	throttle.Throttle
	err error
}

func (t failingResetThrottle) Reset(context.Context, string) error {
	return t.err
}

func TestUnlockLoginErrors(t *testing.T) {
	resetErr := errors.New("reset failed")
	a := &Auth{throttle: failingResetThrottle{Throttle: throttle.Noop(), err: resetErr}}
	qt.Check(t, qt.ErrorIs(a.UnlockLogin(context.Background(), "u1"), resetErr))
	qt.Check(t, qt.ErrorMatches(a.UnlockLogin(context.Background(), ""), "user ID is required"))
}

func TestPassThrottleClearsTheNamedIdentity(t *testing.T) {
	cfg := validConfig()
	cfg.Throttle = contract.ThrottleConfig{Enabled: true, MaxAttempts: 2, Window: time.Minute, LockoutTTL: time.Minute}

	a := newGrantsTestAuth(t, cfg, nil, mfaClient(client.MFAPolicyDisabled))
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(a.checkThrottle(ctx, []string{"id"}, "", "")))
	a.failThrottle(ctx, []string{"id"})

	// The identity is cleared wherever it sits among the keys.
	keys := []string{"ip:192.0.2.1", "id"}
	qt.Assert(t, qt.IsNil(a.checkThrottle(ctx, keys, "", "")))
	a.passThrottle(ctx, keys, "id")

	for range 2 {
		qt.Check(t, qt.IsNil(a.checkThrottle(ctx, []string{"id"}, "", "")))
	}
}
