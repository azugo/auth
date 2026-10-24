package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"azugo.io/auth/apikey"
	"azugo.io/auth/client"
	"azugo.io/auth/event"
	"azugo.io/auth/mfa"
	"azugo.io/auth/mfa/totp"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"github.com/go-quicktest/qt"
)

func apiKeyClient() *client.Client {
	return &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	}
}

func newAPIKeyTestAuth(t *testing.T, opts ...Option) (*Auth, string) {
	t.Helper()

	a := newServiceTestAuth(t, apiKeyClient(), append([]Option{APIKeyStore(apikey.NewMemoryStore())}, opts...)...)

	res, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	return a, res.AccessToken
}

func TestAPIKeyRoundTrip(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: " ci ", Scope: "profile"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Key.Name, "ci"))
	qt.Check(t, qt.Equals(res.Key.UserID, "u1"))
	qt.Check(t, qt.Equals(res.Key.ClientID, "spa"))

	info, key, err := a.ValidateAPIKey(context.Background(), res.Token)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.ID, "u1"))
	qt.Check(t, qt.Equals(info.Scope, "profile"))
	qt.Check(t, qt.Equals(info.ClientID, "spa"))
	qt.Check(t, qt.Equals(info.ACR, ""))
	qt.Check(t, qt.Equals(key.ID, res.Key.ID))
}

func TestAPIKeyDefaultsToCallerScope(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Key.Scope, "openid profile"))
}

func TestAPIKeyScopeCannotExceedCaller(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	_, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci", Scope: "profile admin"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidScope))
}

func TestAPIKeyScopeIsNormalized(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci", Scope: " openid \t profile openid "})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Key.Scope, "openid profile"))
}

func TestAPIKeyScopeNarrowedToOwner(t *testing.T) {
	a, _ := newAPIKeyTestAuth(t)

	qt.Assert(t, qt.IsNil(a.APIKeys().Create(context.Background(), &apikey.Key{ID: "k1", UserID: "u1", ClientID: "spa", Name: "old", Scope: "profile admin", CreatedAt: time.Now(), Hash: apikey.HashSecret("s1")})))

	tok, err := a.codec.Encrypt(token.APIKeyClaims{Type: token.TypeAPIKey, KeyID: "k1", Secret: "s1"})
	qt.Assert(t, qt.IsNil(err))

	info, _, err := a.ValidateAPIKey(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Scope, "profile"))
}

func TestAPIKeyRequiresName(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	_, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "  "})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

func TestAPIKeyExpiryMustBeInFuture(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	past := time.Now().Add(-time.Minute)

	_, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci", ExpiresAt: &past})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

func TestExpiredAPIKeyRefused(t *testing.T) {
	a, _ := newAPIKeyTestAuth(t)

	past := time.Now().Add(-time.Minute)
	qt.Assert(t, qt.IsNil(a.APIKeys().Create(context.Background(), &apikey.Key{ID: "k1", UserID: "u1", Name: "old", CreatedAt: time.Now().Add(-time.Hour), ExpiresAt: &past, Hash: apikey.HashSecret("s1")})))

	tok, err := a.codec.Encrypt(token.APIKeyClaims{Type: token.TypeAPIKey, KeyID: "k1", Secret: "s1"})
	qt.Assert(t, qt.IsNil(err))

	_, _, err = a.ValidateAPIKey(context.Background(), tok)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))
}

func TestAPIKeyExpiryFollowsTheStoredKey(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	soon := time.Now().Add(time.Hour)

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci", ExpiresAt: &soon})
	qt.Assert(t, qt.IsNil(err))

	// A store-side expiry change applies to the already issued token.
	past := time.Now().Add(-time.Minute)
	store := apikey.NewMemoryStore()
	qt.Assert(t, qt.IsNil(store.Create(context.Background(), &apikey.Key{ID: res.Key.ID, UserID: "u1", Name: "ci", CreatedAt: time.Now(), ExpiresAt: &past, Hash: res.Key.Hash})))
	a.apiKeys = store

	_, _, err = a.ValidateAPIKey(context.Background(), res.Token)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))
}

func TestIntrospectWithAPIKeyDecodesEitherKind(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci", Scope: "profile"})
	qt.Assert(t, qt.IsNil(err))

	info, err := a.IntrospectWithAPIKey(context.Background(), res.Token)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Scope, "profile"))

	info, err = a.IntrospectWithAPIKey(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.ID, "u1"))

	_, err = a.IntrospectWithAPIKey(context.Background(), "")
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))
}

func TestAPIKeyNeedsItsSecret(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))

	// The store keeps only the secret's hash.
	key, err := a.APIKeys().Get(context.Background(), res.Key.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(key.Hash, 32))

	// The server secret and key ID alone do not make a working token.
	for _, sec := range []string{"", "guess"} {
		forged, err := a.codec.Encrypt(token.APIKeyClaims{Type: token.TypeAPIKey, KeyID: res.Key.ID, Secret: sec})
		qt.Assert(t, qt.IsNil(err))

		_, _, err = a.ValidateAPIKey(context.Background(), forged)
		qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken), qt.Commentf("secret %q", sec))
	}
}

func TestRevokedAPIKeyRefused(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNil(a.RevokeAPIKey(context.Background(), APIKeyRequest{Token: tok, ID: res.Key.ID})))

	_, _, err = a.ValidateAPIKey(context.Background(), res.Token)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))

	keys, _, err := a.ListAPIKeys(context.Background(), tok, nil, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(keys, 1))
	qt.Check(t, qt.IsNotNil(keys[0].RevokedAt))

	active, _, err := a.ListAPIKeys(context.Background(), tok, &apikey.Filter{ActiveOnly: true}, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(active, 0))
}

func TestRevokeAPIKeyOwnershipEnforced(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	qt.Assert(t, qt.IsNil(a.APIKeys().Create(context.Background(), &apikey.Key{ID: "k1", UserID: "u2", Name: "carol", CreatedAt: time.Now()})))

	err := a.RevokeAPIKey(context.Background(), APIKeyRequest{Token: tok, ID: "k1"})
	qt.Assert(t, qt.IsNotNil(err))

	key, err := a.APIKeys().Get(context.Background(), "k1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(key.Valid()))
}

func TestAPIKeyIsNotASessionCredential(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))

	_, _, err = a.IntrospectToken(context.Background(), res.Token)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))

	// A key cannot mint further keys.
	_, err = a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: res.Token, Name: "nested"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))
}

func TestSessionTokenIsNotAnAPIKey(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	_, _, err := a.ValidateAPIKey(context.Background(), tok)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))
}

func TestAPIKeysDisabledWithoutStore(t *testing.T) {
	a := newServiceTestAuth(t, apiKeyClient())

	res, err := a.Login(context.Background(), LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "secret123"})
	qt.Assert(t, qt.IsNil(err))

	_, err = a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: res.AccessToken, Name: "ci"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
	qt.Check(t, qt.IsNil(a.APIKeys()))

	tok, err := a.codec.Encrypt(token.APIKeyClaims{Type: token.TypeAPIKey, KeyID: "k1"})
	qt.Assert(t, qt.IsNil(err))

	_, _, err = a.ValidateAPIKey(context.Background(), tok)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))
}

func TestAPIKeyCreationHonorsStepUp(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t, StepUp(StepUpPolicyFunc(func(_ context.Context, _ *session.Session, action string) (StepUpRequirement, bool) {
		return StepUpRequirement{MFA: true}, action == ActionCreateAPIKey
	})))

	_, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientUserAuthentication))
}

func TestAPIKeyCreationNeedsARecentAuthenticationByDefault(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)
	qt.Check(t, qt.IsTrue(a.StepUpEnabled()))

	// A session long after its login cannot mint a key.
	_, sess, err := a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))

	sess.AuthTime = time.Now().Add(-time.Hour)
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), sess)))

	_, err = a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientUserAuthentication))

	// The password proves it is the owner.
	res, err := a.BeginReauth(context.Background(), ReauthRequest{Token: tok, Action: ActionCreateAPIKey})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(res.Available, []string{reauthPassword}))
	qt.Assert(t, qt.IsNil(a.VerifyReauth(context.Background(), ReauthVerifyRequest{Token: tok, Password: "secret123"})))

	_, err = a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Check(t, qt.IsNil(err))

	// Revoking a key is protective and needs no step-up by default.
	keys, _, err := a.ListAPIKeys(context.Background(), tok, nil, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(keys, 1))

	sess.AuthTime = time.Now().Add(-time.Hour)
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), sess)))
	qt.Check(t, qt.IsNil(a.RevokeAPIKey(context.Background(), APIKeyRequest{Token: tok, ID: keys[0].ID})))
}

func TestAPIKeyCreationNeedsAFreshFactorByDefault(t *testing.T) {
	store := mfa.NewMemoryStore()
	qt.Assert(t, qt.IsNil(store.Enroll(context.Background(), &mfa.Enrollment{ID: "e1", UserID: "u1", Method: totp.DriverName, CreatedAt: time.Now().Add(-24 * time.Hour)})))

	a, tok := newAPIKeyTestAuth(t, MFAStore(store))

	// A fresh login with only the password does not prove the existing factor.
	_, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientUserAuthentication))
}

func TestRevokeAPIKeyAuditsOnce(t *testing.T) {
	var revoked []event.Event

	a, tok := newAPIKeyTestAuth(t, Events(event.SinkFunc(func(_ context.Context, e event.Event) {
		if e.Type == event.TypeAPIKeyRevoked {
			revoked = append(revoked, e)
		}
	})))

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))

	for range 2 {
		qt.Assert(t, qt.IsNil(a.RevokeAPIKey(context.Background(), APIKeyRequest{Token: tok, ID: res.Key.ID, IP: "192.0.2.1"})))
	}

	qt.Assert(t, qt.HasLen(revoked, 1))
	qt.Check(t, qt.Equals(revoked[0].IP, "192.0.2.1"))
	qt.Check(t, qt.Equals(revoked[0].Detail["key_id"], any(res.Key.ID)))
}

func TestRotateAPIKeyReplacesTheToken(t *testing.T) {
	var rotated []event.Event

	a, tok := newAPIKeyTestAuth(t, Events(event.SinkFunc(func(_ context.Context, e event.Event) {
		if e.Type == event.TypeAPIKeyRotated {
			rotated = append(rotated, e)
		}
	})))

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci", Scope: "profile"})
	qt.Assert(t, qt.IsNil(err))

	next, err := a.RotateAPIKey(context.Background(), APIKeyRequest{Token: tok, ID: res.Key.ID, IP: "192.0.2.1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(next.Key.ID, res.Key.ID))
	qt.Check(t, qt.Equals(next.Key.Scope, "profile"))
	qt.Check(t, qt.IsNotNil(next.Key.RotatedAt))
	qt.Check(t, qt.Not(qt.Equals(next.Token, res.Token)))

	// The previous token stops working at once.
	_, _, err = a.ValidateAPIKey(context.Background(), res.Token)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))

	info, key, err := a.ValidateAPIKey(context.Background(), next.Token)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Scope, "profile"))
	qt.Check(t, qt.DeepEquals(key.RotatedAt, next.Key.RotatedAt))

	qt.Assert(t, qt.HasLen(rotated, 1))
	qt.Check(t, qt.Equals(rotated[0].IP, "192.0.2.1"))
}

func TestRotateAPIKeyRefusesForeignAndRevokedKeys(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	qt.Assert(t, qt.IsNil(a.APIKeys().Create(context.Background(), &apikey.Key{ID: "k1", UserID: "u2", Name: "carol", CreatedAt: time.Now()})))

	_, err := a.RotateAPIKey(context.Background(), APIKeyRequest{Token: tok, ID: "k1"})
	oe, ok := errors.AsType[*OAuthError](err)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(oe.StatusCode(), 404))

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(a.RevokeAPIKey(context.Background(), APIKeyRequest{Token: tok, ID: res.Key.ID})))

	_, err = a.RotateAPIKey(context.Background(), APIKeyRequest{Token: tok, ID: res.Key.ID})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidRequest))
}

func TestRotateAPIKeyNeedsARecentAuthenticationByDefault(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))

	_, sess, err := a.IntrospectToken(context.Background(), tok)
	qt.Assert(t, qt.IsNil(err))

	sess.AuthTime = time.Now().Add(-time.Hour)
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), sess)))

	_, err = a.RotateAPIKey(context.Background(), APIKeyRequest{Token: tok, ID: res.Key.ID})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInsufficientUserAuthentication))

	// The token in use is untouched.
	_, _, err = a.ValidateAPIKey(context.Background(), res.Token)
	qt.Check(t, qt.IsNil(err))
}

// limitedKeys refuses a second key per user.
type limitedKeys struct {
	apikey.Store
}

func (s limitedKeys) Create(ctx context.Context, k *apikey.Key) error {
	keys, _, err := s.List(ctx, k.UserID, nil, nil)
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return fmt.Errorf("%w: at most 1 key per user", apikey.ErrInvalidKey)
	}

	return s.Store.Create(ctx, k)
}

func TestAPIKeyStoreRejectsCreate(t *testing.T) {
	var created []event.Event

	a, tok := newAPIKeyTestAuth(t, APIKeyStore(limitedKeys{apikey.NewMemoryStore()}), Events(event.SinkFunc(func(_ context.Context, e event.Event) {
		if e.Type == event.TypeAPIKeyCreated {
			created = append(created, e)
		}
	})))

	_, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "first"})
	qt.Assert(t, qt.IsNil(err))

	_, err = a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "second"})
	oe, ok := errors.AsType[*OAuthError](err)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(oe.StatusCode(), 400))
	qt.Check(t, qt.Equals(oe.Code, ErrCodeInvalidRequest))
	qt.Check(t, qt.Equals(oe.Description, "invalid api key: at most 1 key per user"))
	qt.Check(t, qt.HasLen(created, 1))
}

func TestChangePasswordRevokesAPIKeysOnlyOnRequest(t *testing.T) {
	var revoked []event.Event

	a, _ := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled), APIKeyStore(apikey.NewMemoryStore()), Events(event.SinkFunc(func(_ context.Context, e event.Event) {
		if e.Type == event.TypeAPIKeyRevoked {
			revoked = append(revoked, e)
		}
	})))

	tok := loginAs(t, a, alice("")).AccessToken

	kept, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "kept"})
	qt.Assert(t, qt.IsNil(err))

	// A plain change leaves the keys valid.
	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: tok, CurrentPassword: "secret123", NewPassword: "brandnew1"})
	qt.Assert(t, qt.IsNil(err))

	_, _, err = a.ValidateAPIKey(context.Background(), kept.Token)
	qt.Check(t, qt.IsNil(err))

	second, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "second"})
	qt.Assert(t, qt.IsNil(err))

	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: tok, CurrentPassword: "brandnew1", NewPassword: "newer-still1", RevokeAPIKeys: true, IP: "192.0.2.1"})
	qt.Assert(t, qt.IsNil(err))

	for _, k := range []APIKeyResult{kept, second} {
		_, _, err = a.ValidateAPIKey(context.Background(), k.Token)
		qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken), qt.Commentf(k.Key.Name))
	}

	qt.Assert(t, qt.HasLen(revoked, 2))
	qt.Check(t, qt.Equals(revoked[0].IP, "192.0.2.1"))
}

// failingKeys fails revoking all keys while failing is set.
type failingKeys struct {
	apikey.Store
	failing string
}

func (s failingKeys) RevokeAll(ctx context.Context, userID string) ([]string, error) {
	if s.failing != "" {
		return nil, errors.New("store unavailable")
	}

	return s.Store.RevokeAll(ctx, userID)
}

func TestChangePasswordRevokesInOneTransaction(t *testing.T) {
	var (
		events []string
		txs    int
	)

	store := &failingKeys{Store: apikey.NewMemoryStore()}

	a, users := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled), APIKeyStore(store),
		Transactor(TransactorFunc(func(ctx context.Context, fn func(ctx context.Context) error) error {
			txs++

			return fn(ctx)
		})),
		Events(event.SinkFunc(func(_ context.Context, e event.Event) {
			events = append(events, e.Type)
		})))

	tok := loginAs(t, a, alice("")).AccessToken

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))

	store.failing = res.Key.ID
	events = nil
	txs = 0

	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: tok, CurrentPassword: "secret123", NewPassword: "brandnew1", RevokeAPIKeys: true})
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeServerError))
	qt.Check(t, qt.Equals(txs, 1))

	// Nothing is announced for a change the transactor rolled back.
	qt.Check(t, qt.HasLen(events, 0))

	// The change ran inside the transaction; this transactor does not roll back.
	qt.Check(t, qt.Equals(users.passwords["alice"], "brandnew1"))
}

func TestForcedPasswordChangeRevokesAPIKeysOnRequest(t *testing.T) {
	var revoked []event.Event

	a, users := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled), APIKeyStore(apikey.NewMemoryStore()), Events(event.SinkFunc(func(_ context.Context, e event.Event) {
		if e.Type == event.TypeAPIKeyRevoked {
			revoked = append(revoked, e)
		}
	})))

	tok := loginAs(t, a, alice("")).AccessToken

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))

	u := users.users["alice"]
	u.RequiresPasswordChange = true
	users.users["alice"] = u

	held := loginAs(t, a, alice(""))
	qt.Assert(t, qt.Equals(held.Status, session.StatusPendingPasswordChange))

	done, err := a.ChangePassword(context.Background(), PasswordChangeRequest{Token: held.StepToken, NewPassword: "brandnew1", RevokeAPIKeys: true, IP: "192.0.2.1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(done.Status, session.StatusActive))

	_, _, err = a.ValidateAPIKey(context.Background(), res.Token)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))

	qt.Assert(t, qt.HasLen(revoked, 1))
	qt.Check(t, qt.Equals(revoked[0].IP, "192.0.2.1"))
}

// revokingKeys revokes a key right after handing out its copy, like a concurrent revoke.
type revokingKeys struct {
	apikey.Store
}

func (s revokingKeys) Get(ctx context.Context, id string) (*apikey.Key, error) {
	k, err := s.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	return k, s.Store.Revoke(ctx, id)
}

func TestRotateAPIKeyLosingARevokeRace(t *testing.T) {
	var rotated int

	store := revokingKeys{apikey.NewMemoryStore()}

	a, tok := newAPIKeyTestAuth(t, Events(event.SinkFunc(func(_ context.Context, e event.Event) {
		if e.Type == event.TypeAPIKeyRotated {
			rotated++
		}
	})))

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNil(store.Store.Create(context.Background(), res.Key)))
	a.apiKeys = store

	_, err = a.RotateAPIKey(context.Background(), APIKeyRequest{Token: tok, ID: res.Key.ID})
	oe, ok := errors.AsType[*OAuthError](err)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(oe.StatusCode(), 404))
	qt.Check(t, qt.Equals(rotated, 0))
}

func TestRevokeAPIKeyLosingARevokeRace(t *testing.T) {
	var revoked int

	store := revokingKeys{apikey.NewMemoryStore()}

	a, tok := newAPIKeyTestAuth(t, Events(event.SinkFunc(func(_ context.Context, e event.Event) {
		if e.Type == event.TypeAPIKeyRevoked {
			revoked++
		}
	})))

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNil(store.Store.Create(context.Background(), res.Key)))
	a.apiKeys = store

	// The other revoke emits; this one succeeds without a second event.
	qt.Check(t, qt.IsNil(a.RevokeAPIKey(context.Background(), APIKeyRequest{Token: tok, ID: res.Key.ID})))
	qt.Check(t, qt.Equals(revoked, 0))
}

func TestChangePasswordDropsFederatedHintsOnlyWhenStored(t *testing.T) {
	store := &failingKeys{Store: apikey.NewMemoryStore()}

	a, _ := newAccountTestAuth(t, mfaClient(client.MFAPolicyDisabled), APIKeyStore(store),
		Transactor(TransactorFunc(func(ctx context.Context, fn func(ctx context.Context) error) error {
			return fn(ctx)
		})))

	tok := loginAs(t, a, alice("")).AccessToken

	other := loginAs(t, a, alice("")).AccessToken
	_, sess, err := a.IntrospectToken(context.Background(), other)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(setSynced(context.Background(), a.fedIDTokens, sess.ID, "idt")))

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))

	// A failed unit keeps the hint of the session it would have revoked.
	store.failing = res.Key.ID

	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: tok, CurrentPassword: "secret123", NewPassword: "brandnew1", RevokeAPIKeys: true})
	qt.Assert(t, qt.IsNotNil(err))

	idt, err := a.fedIDTokens.Get(context.Background(), sess.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(idt, "idt"))

	// A stored change drops it; this transactor does not roll back, so a new session is used.
	store.failing = ""

	next := loginAs(t, a, LoginRequest{Credentials: ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "brandnew1"}).AccessToken
	_, sess, err = a.IntrospectToken(context.Background(), next)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(setSynced(context.Background(), a.fedIDTokens, sess.ID, "idt")))

	_, err = a.ChangePassword(context.Background(), PasswordChangeRequest{Token: tok, CurrentPassword: "brandnew1", NewPassword: "newer-still1", RevokeAPIKeys: true})
	qt.Assert(t, qt.IsNil(err))

	idt, _ = a.fedIDTokens.Get(context.Background(), sess.ID)
	qt.Check(t, qt.Equals(idt, ""))
}

func TestAPIKeyFollowsItsClient(t *testing.T) {
	a, tok := newAPIKeyTestAuth(t)

	res, err := a.CreateAPIKey(context.Background(), CreateAPIKeyRequest{Token: tok, Name: "ci"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Key.Scope, "openid profile"))

	// Narrowing the client's scopes narrows the key.
	registry := client.NewMemoryRegistry(apiKeyClient())
	cl := apiKeyClient()
	cl.Scopes = []string{"profile"}
	registry.Add(cl)
	a.clients = registry

	info, _, err := a.ValidateAPIKey(context.Background(), res.Token)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Scope, "profile"))

	// A removed client takes its keys with it.
	a.clients = client.NewMemoryRegistry()

	_, _, err = a.ValidateAPIKey(context.Background(), res.Token)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))

	_, err = a.IntrospectWithAPIKey(context.Background(), res.Token)
	qt.Check(t, qt.Equals(oauthErrorCode(t, err), ErrCodeInvalidToken))
}
