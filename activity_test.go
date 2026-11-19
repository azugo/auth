package auth

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
)

// countingStore counts the session loads and activity writes reaching the store.
type countingStore struct {
	session.Store
	gets    atomic.Int32
	touches atomic.Int32
}

func (s *countingStore) Get(ctx context.Context, id string) (*session.Session, error) {
	s.gets.Add(1)

	return s.Store.Get(ctx, id)
}

func (s *countingStore) Touch(ctx context.Context, id string, idleExpiresAt time.Time) error {
	s.touches.Add(1)

	return s.Store.Touch(ctx, id, idleExpiresAt)
}

// newActivityTestAuth signs alice in through cl with a 30m idle TTL over a counting store.
func newActivityTestAuth(t *testing.T, cl *client.Client) (*Auth, *countingStore, LoginResult) {
	t.Helper()

	priv, pub := genTestRSAKeyPair(t)
	cfg := validConfig()
	cfg.Keys = keySetConfig(priv, pub)
	cfg.SessionIdleTTL = 30 * time.Minute

	users := fakeUsers{
		users:     map[string]UserInfo{"alice": {ID: "u1", Name: "Alice", Scope: "openid profile"}},
		passwords: map[string]string{"alice": "secret123"},
	}
	store := &countingStore{Store: session.NewMemoryStore()}

	a, err := New(newApp(t), cfg, users, store, client.NewMemoryRegistry(cl))
	qt.Assert(t, qt.IsNil(err))

	res, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: cl.ID}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	return a, store, res
}

func TestRecordActivityWritesOncePerStep(t *testing.T) {
	a, store, res := newActivityTestAuth(t, portalClient())
	ctx := context.Background()

	_, sess, err := a.IntrospectToken(ctx, res.AccessToken)
	qt.Assert(t, qt.IsNil(err))

	// A deadline less than a step old is not written again.
	a.RecordActivity(ctx, sess)
	qt.Check(t, qt.Equals(store.touches.Load(), int32(0)))

	sess.IdleExpiresAt = time.Now().Add(26 * time.Minute)
	qt.Assert(t, qt.IsNil(store.Update(ctx, sess)))

	a.RecordActivity(ctx, sess)
	qt.Check(t, qt.Equals(store.touches.Load(), int32(1)))
	qt.Check(t, qt.IsTrue(time.Until(sess.IdleExpiresAt) > 29*time.Minute))

	stored, err := store.Store.Get(ctx, sess.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(stored.IdleExpiresAt, sess.IdleExpiresAt))

	// Without an idle TTL the deadline given before is cleared once, then nothing is written.
	a.Config().SessionIdleTTL = 0

	for range 2 {
		a.RecordActivity(ctx, sess)
	}

	qt.Check(t, qt.Equals(store.touches.Load(), int32(2)))
	qt.Check(t, qt.IsTrue(sess.IdleExpiresAt.IsZero()))

	stored, err = store.Store.Get(ctx, sess.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(stored.IdleExpiresAt.IsZero()))
}

func TestRecordSessionActivityLoadsOncePerStep(t *testing.T) {
	cl := portalClient()
	cl.AccessTokenType = client.AccessTokenTypeJWT

	a, store, res := newActivityTestAuth(t, cl)
	ctx := context.Background()

	_, claims, err := a.ValidateJWTAccessToken(ctx, res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(claims.SessionID != ""))

	sess, err := store.Store.Get(ctx, claims.SessionID)
	qt.Assert(t, qt.IsNil(err))

	sess.IdleExpiresAt = time.Now().Add(time.Minute)
	qt.Assert(t, qt.IsNil(store.Update(ctx, sess)))

	gets := store.gets.Load()

	for range 3 {
		a.RecordSessionActivity(ctx, claims.SessionID)
	}

	qt.Check(t, qt.Equals(store.gets.Load(), gets+1))
	qt.Check(t, qt.Equals(store.touches.Load(), int32(1)))

	sess, err = store.Store.Get(ctx, claims.SessionID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(time.Until(sess.IdleExpiresAt) > 29*time.Minute))
}

func TestKeepAlive(t *testing.T) {
	a, store, res := newActivityTestAuth(t, portalClient())
	ctx := context.Background()

	_, err := a.KeepAlive(ctx, "")
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))

	_, sess, err := a.IntrospectToken(ctx, res.AccessToken)
	qt.Assert(t, qt.IsNil(err))

	sess.IdleExpiresAt = time.Now().Add(time.Minute)
	qt.Assert(t, qt.IsNil(store.Update(ctx, sess)))

	kept, err := a.KeepAlive(ctx, res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(time.Until(kept.IdleExpiresAt) > 29*time.Minute))
	qt.Check(t, qt.Equals(kept.ExpiresAt, sess.ExpiresAt))

	// An idle session cannot be kept alive.
	kept.IdleExpiresAt = time.Now().Add(-time.Second)
	qt.Assert(t, qt.IsNil(store.Update(ctx, kept)))

	_, err = a.KeepAlive(ctx, res.AccessToken)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))
}

func TestKeepAliveAcceptsJWT(t *testing.T) {
	cl := portalClient()
	cl.AccessTokenType = client.AccessTokenTypeJWT

	a, store, res := newActivityTestAuth(t, cl)
	ctx := context.Background()

	_, claims, err := a.ValidateJWTAccessToken(ctx, res.AccessToken)
	qt.Assert(t, qt.IsNil(err))

	sess, err := store.Store.Get(ctx, claims.SessionID)
	qt.Assert(t, qt.IsNil(err))

	sess.IdleExpiresAt = time.Now().Add(time.Minute)
	qt.Assert(t, qt.IsNil(store.Update(ctx, sess)))

	kept, err := a.KeepAlive(ctx, res.AccessToken)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(kept.ID, claims.SessionID))
	qt.Check(t, qt.IsTrue(time.Until(kept.IdleExpiresAt) > 29*time.Minute))

	// A tampered JWT is refused.
	_, err = a.KeepAlive(ctx, res.AccessToken+"x")
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))
}

func TestKeepAliveRefusesAnotherClientsToken(t *testing.T) {
	for name, typ := range map[string]client.AccessTokenType{
		"opaque": client.AccessTokenTypeIntrospect,
		"jwt":    client.AccessTokenTypeJWT,
	} {
		t.Run(name, func(t *testing.T) {
			priv, pub := genTestRSAKeyPair(t)
			cfg := validConfig()
			cfg.Keys = keySetConfig(priv, pub)
			cfg.SessionIdleTTL = 30 * time.Minute

			cl := codeClient()
			cl.AccessTokenType = typ

			a := newGrantsTestAuth(t, cfg, nil, portalClient(), cl)
			ctx := context.Background()
			cookie := login(t, a)

			res, err := a.AuthorizationCodeGrant(ctx, AuthorizationCodeGrantRequest{
				Credentials:  ClientCredentials{ClientID: "web"},
				Code:         authorizeCode(t, a, cookie, "profile", ""),
				RedirectURI:  "https://web.example/callback",
				CodeVerifier: pkceVerifier,
			})
			qt.Assert(t, qt.IsNil(err))

			_, err = a.KeepAlive(ctx, res.AccessToken)
			qt.Check(t, qt.ErrorIs(err, ErrFirstPartyRequired))

			// The portal's own session cookie still keeps the session alive.
			_, err = a.KeepAlive(ctx, cookie)
			qt.Check(t, qt.IsNil(err))
		})
	}
}

func TestRecordSessionActivityMarkerEndsWhenWriteIsDue(t *testing.T) {
	cl := portalClient()
	cl.AccessTokenType = client.AccessTokenTypeJWT

	a, store, res := newActivityTestAuth(t, cl)
	ctx := context.Background()

	_, claims, err := a.ValidateJWTAccessToken(ctx, res.AccessToken)
	qt.Assert(t, qt.IsNil(err))

	// A 2s TTL has a 200ms step; the deadline was last moved 150ms ago, so a write is due in 50ms.
	a.Config().SessionIdleTTL = 2 * time.Second

	sess, err := store.Store.Get(ctx, claims.SessionID)
	qt.Assert(t, qt.IsNil(err))

	sess.IdleExpiresAt = time.Now().Add(1850 * time.Millisecond)
	qt.Assert(t, qt.IsNil(store.Update(ctx, sess)))

	a.RecordSessionActivity(ctx, claims.SessionID)
	qt.Check(t, qt.Equals(store.touches.Load(), int32(0)))

	// Within the step but past the due time the session is loaded and written again.
	time.Sleep(120 * time.Millisecond)

	a.RecordSessionActivity(ctx, claims.SessionID)
	qt.Check(t, qt.Equals(store.touches.Load(), int32(1)))
}
