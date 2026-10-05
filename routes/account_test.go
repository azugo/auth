package routes

import (
	"context"
	"sync"
	"testing"
	"time"

	"azugo.io/auth"
	"azugo.io/auth/client"
	"azugo.io/auth/reset"
	"azugo.io/auth/session"

	"azugo.io/core"
	"azugo.io/core/config"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// accountStubUsers implements every self-service extension over stubUsers.
type accountStubUsers struct {
	mu sync.Mutex
	stubUsers
	password  string
	profile   map[string]any
	delivered chan string
	// registered is the account Register created, if any.
	registered *auth.UserInfo
}

func (s *accountStubUsers) Authenticate(_ context.Context, _, password string) (auth.UserInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if password != s.password {
		return auth.UserInfo{}, auth.ErrInvalidCredentials
	}

	return s.info, nil
}

func (s *accountStubUsers) GetUser(_ context.Context, id string) (auth.UserInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.registered != nil && id == s.registered.ID {
		return *s.registered, nil
	}

	if id != s.info.ID {
		return auth.UserInfo{}, auth.ErrUserNotFound
	}

	return s.info, nil
}

func (s *accountStubUsers) Register(_ context.Context, req auth.RegistrationRequest) (auth.UserInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req.Username == "alice" {
		return auth.UserInfo{}, auth.ErrUserAlreadyExists
	}

	s.registered = &auth.UserInfo{ID: "u9", Name: req.Username, Email: req.Email, Scope: "openid"}

	return *s.registered, nil
}

func (s *accountStubUsers) ChangePassword(_ context.Context, _, currentPassword, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if currentPassword != s.password {
		return auth.ErrInvalidCredentials
	}

	s.password = newPassword

	return nil
}

func (s *accountStubUsers) SetPassword(_ context.Context, _, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.password = newPassword
	s.info.RequiresPasswordChange = false

	return nil
}

func (s *accountStubUsers) FindUser(_ context.Context, identifier string) (auth.UserInfo, error) {
	if identifier != s.info.Email {
		return auth.UserInfo{}, auth.ErrUserNotFound
	}

	return s.info, nil
}

// Available implements reset.Deliverer: every account can be mailed.
func (s *accountStubUsers) Available(auth.UserInfo) bool { return true }

// Deliver implements reset.Deliverer by handing the secret to the test.
func (s *accountStubUsers) Deliver(_ context.Context, _ auth.UserInfo, _, secret string) error {
	s.delivered <- secret

	return nil
}

// resetMethods delivers mailed links to the test.
func (s *accountStubUsers) resetMethods() reset.Registry {
	return reset.Methods(map[string]reset.Method{"email": reset.Link(s)})
}

func (s *accountStubUsers) ResetPassword(ctx context.Context, userID, newPassword string) error {
	return s.SetPassword(ctx, userID, newPassword)
}

func (s *accountStubUsers) GetProfile(context.Context, string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.profile, nil
}

func (s *accountStubUsers) UpdateProfile(_ context.Context, _ string, data map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.profile = data

	return nil
}

func accountTestAuth(t *testing.T, cl *client.Client) (*auth.Auth, *accountStubUsers) {
	t.Helper()

	app := core.New()

	conf := config.New()
	qt.Assert(t, qt.IsNil(conf.Load(nil, conf, string(app.Env()))))
	app.SetConfig(nil, conf)
	t.Cleanup(app.Stop)

	cfg := &auth.Configuration{
		Secret:   "0123456789abcdef0123456789abcdef",
		SameSite: "strict",
		Issuer:   "https://issuer.example",
	}

	users := &accountStubUsers{
		stubUsers: stubUsers{info: auth.UserInfo{ID: "u1", Name: "Alice", Email: "alice@example.com", Scope: "openid profile email"}},
		password:  "right",
		delivered: make(chan string, 8),
	}

	a, err := auth.New(app, cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(cl), auth.PasswordResetRegistry(users.resetMethods()))
	qt.Assert(t, qt.IsNil(err))

	return a, users
}

type resetBody struct {
	Status      string   `json:"status"`
	ResetToken  string   `json:"reset_token"`
	Available   []string `json:"available"`
	Selected    string   `json:"selected"`
	Interaction string   `json:"interaction"`
}

func TestBindSkipsAccountWithoutInterfaces(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{ID: "spa", GrantTypes: []string{client.GrantTypePassword}, AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON})

	app := newTestApp(t)
	h := Bind(app, "/auth", a)

	qt.Check(t, qt.IsNil(h.Account.Register))
	qt.Check(t, qt.IsNil(h.Account.ChangePassword))
	qt.Check(t, qt.IsNil(h.Account.RequestPasswordReset))
	qt.Check(t, qt.IsNil(h.Account.Profile))

	tc := app.TestClient()

	for _, path := range []string{"/auth/account/register", "/auth/account/password", "/auth/account/password/reset"} {
		resp, err := tc.PostJSON(path, map[string]any{})
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(resp.StatusCode(), 404), qt.Commentf("%s", path))
		fasthttp.ReleaseResponse(resp)
	}
}

func TestRegisterAnswersCreatedWithoutSignIn(t *testing.T) {
	a, _ := accountTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
		RegistrationPolicy: client.RegistrationPolicyRequireLogin,
	})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().PostJSON("/auth/account/register", map[string]any{"client_id": "spa", "username": "bob", "password": "pw123456"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 201))

	created := decodeJSON[struct {
		UserID string `json:"user_id"`
	}](t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(created.UserID, "u9"))
}

func TestAccountRoutesEndToEndJSON(t *testing.T) {
	a, users := accountTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
		RegistrationPolicy: client.RegistrationPolicySignIn,
	})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	// Registration signs the new account in.
	resp, err := tc.PostJSON("/auth/account/register", map[string]any{"client_id": "spa", "username": "bob", "email": "bob@example.com", "password": "pw123456"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	registered := decodeJSON[tokenBody](t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.IsTrue(registered.AccessToken != ""))

	resp, err = tc.PostForm("/auth/account/register", map[string]any{"client_id": "spa", "username": "alice", "password": "pw123456"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 409))
	fasthttp.ReleaseResponse(resp)

	// A forced password change holds the login at 202 until the new password is set.
	users.info.RequiresPasswordChange = true

	resp, err = tc.PostForm("/auth/token", map[string]any{"grant_type": "password", "client_id": "spa", "username": "alice", "password": "right"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 202))

	pending := decodeJSON[pendingBody](t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(pending.Status, string(session.StatusPendingPasswordChange)))
	qt.Assert(t, qt.IsTrue(pending.StepToken != ""))

	step := tc.WithHeader("Authorization", "Bearer "+pending.StepToken)

	resp, err = tc.PostJSON("/auth/account/password", map[string]any{"new_password": "fresh123"}, step)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	tokens := decodeJSON[tokenBody](t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsTrue(tokens.AccessToken != ""))
	qt.Check(t, qt.Equals(users.password, "fresh123"))

	bearer := tc.WithHeader("Authorization", "Bearer "+tokens.AccessToken)

	// A self-service change on the active session verifies the current password.
	resp, err = tc.PostJSON("/auth/account/password", map[string]any{"current_password": "nope", "new_password": "other123"}, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 400))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.PostJSON("/auth/account/password", map[string]any{"current_password": "fresh123", "new_password": "other123"}, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 204))
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(users.password, "other123"))

	// Profile round-trip.
	resp, err = tc.PutJSON("/auth/account/profile", map[string]any{"locale": "lv"}, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 204))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.Get("/auth/account/profile", bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	profile := decodeJSON[map[string]any](t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.DeepEquals(profile, map[string]any{"locale": "lv"}))

	// Reset: the request is always 202 with the same shape, the confirmation signs in and
	// cuts other sessions.
	resp, err = tc.PostJSON("/auth/account/password/reset", map[string]any{"client_id": "spa", "identifier": "nobody@example.com"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 202))

	decoy := decodeJSON[resetBody](t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.HasLen(users.delivered, 0))
	qt.Check(t, qt.Equals(decoy.Status, "pending"))
	qt.Check(t, qt.DeepEquals(decoy.Available, []string{"email"}))
	qt.Check(t, qt.Equals(decoy.Interaction, "link"))

	resp, err = tc.PostJSON("/auth/account/password/reset", map[string]any{"client_id": "spa", "identifier": "alice@example.com"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 202))

	opened := decodeJSON[resetBody](t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsTrue(opened.ResetToken != ""))

	var secret string

	select {
	case secret = <-users.delivered:
	case <-time.After(2 * time.Second):
		t.Fatal("no reset secret was delivered")
	}

	// The status poll takes the reset token as a bearer credential.
	resp, err = tc.Get("/auth/account/password/reset/status", tc.WithHeader("Authorization", "Bearer "+opened.ResetToken))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.PostJSON("/auth/account/password/reset/confirm", map[string]any{"reset_token": opened.ResetToken, "response": map[string]any{"token": "bogus"}, "new_password": "reset123"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 400))
	fasthttp.ReleaseResponse(resp)

	// A plain form carries the proof as a token field.
	resp, err = tc.PostForm("/auth/account/password/reset/confirm", map[string]any{"reset_token": opened.ResetToken, "token": secret, "new_password": "reset123"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	reset := decodeJSON[tokenBody](t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.IsTrue(reset.AccessToken != ""))
	qt.Check(t, qt.Equals(users.password, "reset123"))

	resp, err = tc.Get("/auth/session", bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 401))
	fasthttp.ReleaseResponse(resp)
}
