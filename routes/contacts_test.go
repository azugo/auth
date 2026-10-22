package routes

import (
	"context"
	"slices"
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

// contactStubUsers holds one account with a changeable list of email contacts.
type contactStubUsers struct {
	mu     sync.Mutex
	emails []auth.Contact
	codes  chan string
}

func (s *contactStubUsers) info() auth.UserInfo {
	return auth.UserInfo{ID: "u1", Name: "Alice", Scope: "openid profile email", Contacts: map[string][]auth.Contact{auth.ChannelEmail: slices.Clone(s.emails)}}
}

func (s *contactStubUsers) Authenticate(context.Context, string, string) (auth.UserInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.info(), nil
}

func (s *contactStubUsers) GetUser(context.Context, string) (auth.UserInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.info(), nil
}

func (s *contactStubUsers) FindContact(context.Context, string, string) (auth.UserInfo, error) {
	return auth.UserInfo{}, auth.ErrUserNotFound
}

func (s *contactStubUsers) VerifyContact(_ context.Context, _, _, address string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.emails = append(s.emails, auth.Contact{Address: address, Verified: true})

	return nil
}

func (s *contactStubUsers) RemoveContact(_ context.Context, _, _, address string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.emails = slices.DeleteFunc(s.emails, func(c auth.Contact) bool { return c.Address == address })

	return nil
}

func (s *contactStubUsers) SetPrimaryContact(_ context.Context, _, _, address string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.emails {
		s.emails[i].Primary = s.emails[i].Address == address
	}

	return nil
}

func (s *contactStubUsers) VerifyPassword(_ context.Context, _, password string) error {
	if password != "right" {
		return auth.ErrInvalidCredentials
	}

	return nil
}

func (s *contactStubUsers) Available(auth.UserInfo) bool { return true }

func (s *contactStubUsers) Deliver(_ context.Context, _ auth.UserInfo, _ *reset.Request, secret string) error {
	s.codes <- secret

	return nil
}

type contactsBody map[string][]struct {
	Address  string `json:"address"`
	Verified bool   `json:"verified"`
	Primary  bool   `json:"primary"`
}

// newContactTestAuth builds an auth over contactStubUsers with email contact verification.
func newContactTestAuth(t *testing.T, opts ...auth.Option) (*auth.Auth, *contactStubUsers) {
	t.Helper()

	app := core.New()

	conf := config.New()
	qt.Assert(t, qt.IsNil(conf.Load(nil, conf, string(app.Env()))))
	app.SetConfig(nil, conf)
	t.Cleanup(app.Stop)

	users := &contactStubUsers{emails: []auth.Contact{{Address: "alice@example.com", Verified: true, Primary: true}}, codes: make(chan string, 4)}

	a, err := auth.New(app, &auth.Configuration{Secret: "0123456789abcdef0123456789abcdef", SameSite: "strict", Issuer: "https://issuer.example"},
		users, session.NewMemoryStore(), client.NewMemoryRegistry(&client.Client{
			ID: "spa", GrantTypes: []string{client.GrantTypePassword},
			AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
		}), append([]auth.Option{auth.ContactVerification(auth.ChannelEmail, reset.Code(users, 6))}, opts...)...)
	qt.Assert(t, qt.IsNil(err))

	return a, users
}

func TestContactRoutes(t *testing.T) {
	a, users := newContactTestAuth(t)

	login := loginFor(t, a, "spa")

	testApp := newTestApp(t)
	Bind(testApp, "/auth", a)

	tc := testApp.TestClient()
	bearer := tc.WithHeader("Authorization", "Bearer "+login.AccessToken)

	list := func() contactsBody {
		resp, err := tc.Get("/auth/account/contacts", bearer)
		defer fasthttp.ReleaseResponse(resp)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

		return decodeJSON[contactsBody](t, resp)
	}

	qt.Check(t, qt.Equals(len(list()[auth.ChannelEmail]), 1))

	// A new address is verified through the delivered code before it joins the account.
	resp, err := tc.PostJSON("/auth/account/contacts", map[string]any{"channel": "email", "address": "second@example.com"}, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 202))

	added := decodeJSON[struct {
		Request     string `json:"request"`
		Interaction string `json:"interaction"`
	}](t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(added.Interaction, reset.InteractionCode))
	qt.Check(t, qt.Equals(len(list()[auth.ChannelEmail]), 1))

	resp, err = tc.PostJSON("/auth/account/contact/verify", map[string]any{"request": added.Request, "response": map[string]any{"code": <-users.codes}})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 204))
	fasthttp.ReleaseResponse(resp)

	qt.Check(t, qt.Equals(len(list()[auth.ChannelEmail]), 2))

	resp, err = tc.PostJSON("/auth/account/contacts/primary", map[string]any{"channel": "email", "address": "second@example.com"}, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 204))
	fasthttp.ReleaseResponse(resp)

	qt.Check(t, qt.IsTrue(list()[auth.ChannelEmail][1].Primary))

	resp, err = tc.PostForm("/auth/account/contacts/remove", map[string]any{"channel": "email", "address": "alice@example.com"}, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 204))
	fasthttp.ReleaseResponse(resp)

	qt.Check(t, qt.Equals(len(list()[auth.ChannelEmail]), 1))

	// A cookie-authenticated change must come from a page of this origin.
	cookie := tc.WithCookie(a.Config().CookieName, login.Cookie.Value)

	for _, path := range []string{"/auth/account/contacts", "/auth/account/contacts/primary", "/auth/account/contacts/remove"} {
		resp, err = tc.PostJSON(path, map[string]any{"channel": "email", "address": "second@example.com"}, cookie, tc.WithHeader("Sec-Fetch-Site", "cross-site"))
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(resp.StatusCode(), 403), qt.Commentf(path))
		fasthttp.ReleaseResponse(resp)
	}
}

func TestStepUpRoutes(t *testing.T) {
	a, _ := newContactTestAuth(t, auth.StepUp(auth.StepUpPolicyFunc(func(_ context.Context, _ *session.Session, action string) (auth.StepUpRequirement, bool) {
		return auth.StepUpRequirement{Methods: []string{"pwd"}, MaxAge: 5 * time.Minute}, action == auth.ActionAddContact
	})))

	login := loginFor(t, a, "spa")

	// The login is older than the policy allows.
	_, sess, err := a.IntrospectToken(context.Background(), login.AccessToken)
	qt.Assert(t, qt.IsNil(err))

	sess.AuthTime = time.Now().Add(-time.Hour)
	qt.Assert(t, qt.IsNil(a.Sessions().Update(context.Background(), sess)))

	testApp := newTestApp(t)
	Bind(testApp, "/auth", a)

	tc := testApp.TestClient()
	bearer := tc.WithHeader("Authorization", "Bearer "+login.AccessToken)
	add := map[string]any{"channel": "email", "address": "second@example.com"}

	resp, err := tc.PostJSON("/auth/account/contacts", add, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 401))
	qt.Check(t, qt.Matches(string(resp.Header.Peek("WWW-Authenticate")), `.*error="insufficient_user_authentication".*`))
	fasthttp.ReleaseResponse(resp)

	// The re-authentication endpoints take plain form fields too.
	resp, err = tc.PostForm("/auth/session/reauth", map[string]any{"action": auth.ActionAddContact}, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	begun := decodeJSON[struct {
		Available []string `json:"available"`
	}](t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.DeepEquals(begun.Available, []string{"password"}))

	resp, err = tc.PostForm("/auth/session/reauth/verify", map[string]any{"password": "right"}, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 204))
	fasthttp.ReleaseResponse(resp)

	// Re-authenticated in place, the same session may now add the contact.
	resp, err = tc.PostJSON("/auth/account/contacts", add, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 202))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.PostJSON("/auth/session/reauth", map[string]any{"action": auth.ActionAddContact}, tc.WithCookie(a.Config().CookieName, login.Cookie.Value), tc.WithHeader("Sec-Fetch-Site", "cross-site"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 403))
	fasthttp.ReleaseResponse(resp)
}
