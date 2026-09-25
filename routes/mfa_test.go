package routes

import (
	"context"
	"testing"
	"time"

	"azugo.io/auth"
	"azugo.io/auth/client"
	"azugo.io/auth/internal/mfatest"
	"azugo.io/auth/mfa"
	"azugo.io/auth/mfa/totp"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

type enrollBody struct {
	Method string         `json:"method"`
	Data   map[string]any `json:"data"`
}

type tokenBody struct {
	AccessToken string `json:"access_token"`
}

type userinfoBody struct {
	AMR []string `json:"amr"`
}

type acrDoc struct {
	ACRValuesSupported []string `json:"acr_values_supported"`
}

type pendingBody struct {
	Status      string         `json:"status"`
	StepToken   string         `json:"step_token"`
	Available   []string       `json:"available"`
	Selected    string         `json:"selected"`
	Interaction string         `json:"interaction"`
	Data        map[string]any `json:"data"`
}

func mfaTestAuth(t *testing.T, cl *client.Client) (*auth.Auth, mfa.Store) {
	t.Helper()

	store := mfa.NewMemoryStore()
	a := newTestAuthWithOpts(t, session.NewMemoryStore(), []auth.Option{auth.MFAStore(store)}, cl)
	a.Config().MFAMethods = []auth.MFAMethodConfig{{Driver: mfatest.DriverName, Config: map[string]string{"callback_secret": "hook-secret"}}}

	return a, store
}

func TestMFARoutesEndToEndJSON(t *testing.T) {
	a, store := mfaTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
		MFAPolicy: client.MFAPolicyOptional,
	})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	// First login: nothing enrolled, so it is active straight away.
	first := loginFor(t, a, "spa")
	bearer := tc.WithHeader("Authorization", "Bearer "+first.AccessToken)

	resp, err := tc.Get("/auth/mfa/methods", bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	methods := decodeJSON[[]auth.MFAMethodInfo](t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.IsTrue(len(methods) >= 2))

	resp, err = tc.PostJSON("/auth/mfa/enroll/totp", map[string]any{}, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	enroll := decodeJSON[enrollBody](t, resp)
	fasthttp.ReleaseResponse(resp)

	seed, _ := enroll.Data["secret"].(string)
	qt.Assert(t, qt.IsTrue(seed != ""))

	code, err := totp.GenerateCode(seed, time.Now())
	qt.Assert(t, qt.IsNil(err))

	resp, err = tc.PostJSON("/auth/mfa/enroll/totp/finish", map[string]any{"label": "Phone", "response": map[string]any{"code": code}}, bearer)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	finished := decodeJSON[struct {
		EnrollmentID string `json:"enrollment_id"`
	}](t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsTrue(finished.EnrollmentID != ""))

	enrolled, err := mfa.Enrolled(context.Background(), store, "u1", totp.DriverName)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(enrolled, 1))
	qt.Check(t, qt.Equals(enrolled[0].Label, "Phone"))

	resp, err = tc.Get("/auth/mfa/methods", bearer)
	qt.Assert(t, qt.IsNil(err))

	methods = decodeJSON[[]auth.MFAMethodInfo](t, resp)
	fasthttp.ReleaseResponse(resp)

	for _, m := range methods {
		if m.Method == totp.DriverName {
			qt.Assert(t, qt.HasLen(m.Enrollments, 1))
			qt.Check(t, qt.Equals(m.Enrollments[0].ID, finished.EnrollmentID))
		}
	}

	// Second login: held at pending_mfa with a 202.
	resp, err = tc.PostForm("/auth/token", map[string]any{
		"grant_type": "password", "client_id": "spa", "username": "alice", "password": "right",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 202))

	pending := decodeJSON[pendingBody](t, resp)
	fasthttp.ReleaseResponse(resp)

	qt.Check(t, qt.Equals(pending.Status, string(session.StatusPendingMFA)))
	qt.Check(t, qt.DeepEquals(pending.Available, []string{"totp"}))
	qt.Check(t, qt.Equals(pending.Selected, "totp"))
	qt.Check(t, qt.Equals(pending.Interaction, "code"))
	qt.Assert(t, qt.IsTrue(pending.StepToken != ""))

	step := tc.WithHeader("Authorization", "Bearer "+pending.StepToken)

	// The step token is not an access token.
	resp, err = tc.Get("/auth/session", step)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 401))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.PostJSON("/auth/mfa/verify", map[string]any{"response": map[string]any{"code": "000000"}}, step)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 400))
	fasthttp.ReleaseResponse(resp)

	// The enrollment consumed the current time step; the next one is still within skew.
	code, err = totp.GenerateCode(seed, time.Now().Add(30*time.Second))
	qt.Assert(t, qt.IsNil(err))

	resp, err = tc.PostJSON("/auth/mfa/verify", map[string]any{"response": map[string]any{"code": code}}, step)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	tokens := decodeJSON[tokenBody](t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsTrue(tokens.AccessToken != ""))

	resp, err = tc.Get("/auth/userinfo", tc.WithHeader("Authorization", "Bearer "+tokens.AccessToken))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))

	ui := decodeJSON[userinfoBody](t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.DeepEquals(ui.AMR, []string{"pwd", "otp", "mfa"}))

	resp, err = tc.Delete("/auth/mfa/enroll/totp", tc.WithHeader("Authorization", "Bearer "+tokens.AccessToken))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 204))
	fasthttp.ReleaseResponse(resp)
}

func TestMFARoutesRedirectModeWithFormsAndCookie(t *testing.T) {
	a, store := mfaTestAuth(t, &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeRedirect,
		MFAPolicy: client.MFAPolicyOptional, StepRedirectURI: "/mfa",
	})
	qt.Assert(t, qt.IsNil(store.Enroll(context.Background(), &mfa.Enrollment{ID: "phone", UserID: "u1", Method: mfatest.DriverName, Secret: []byte("phone")})))

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	resp, err := tc.PostForm("/auth/token", map[string]any{
		"grant_type": "password", "client_id": "ssr", "username": "alice", "password": "right", "return_to": "/home",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 303))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("Location")), "/mfa?return_to=%2Fhome"))

	var cookie fasthttp.Cookie
	cookie.SetKey("__Secure-" + a.Config().CookieName)
	qt.Assert(t, qt.IsTrue(resp.Header.Cookie(&cookie)))
	fasthttp.ReleaseResponse(resp)

	withCookie := tc.WithHeader("Cookie", a.Config().CookieName+"="+string(cookie.Value()))

	// While pending, a redirect-mode client is always sent back to its step page.
	resp, err = tc.Get("/auth/mfa/status", withCookie)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 302))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("Location")), "/mfa?return_to=%2F"))
	fasthttp.ReleaseResponse(resp)

	// The login client cannot approve its own push challenge: it stays pending.
	resp, err = tc.PostJSON("/auth/mfa/verify", map[string]any{"response": map[string]any{"approved": true}, "return_to": "/home"}, withCookie)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 303))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("Location")), "/mfa?return_to=%2Fhome"))
	fasthttp.ReleaseResponse(resp)

	// Approval lands out-of-band; the next poll completes the step and lands on return_to.
	m, err := a.MFAMethods().Get(context.Background(), mfatest.DriverName)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(mfatest.Approve(m, "u1", true)))

	resp, err = tc.Get("/auth/mfa/status?return_to=/home", withCookie)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 302))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("Location")), "/home"))
	qt.Check(t, qt.StringContains(string(resp.Header.Peek("Set-Cookie")), a.Config().CookieName+"="))
	fasthttp.ReleaseResponse(resp)
}

func TestMFACallbackSettlesChallenge(t *testing.T) {
	a, store := mfaTestAuth(t, &client.Client{ID: "spa"})
	qt.Assert(t, qt.IsNil(store.Enroll(context.Background(), &mfa.Enrollment{ID: "phone", UserID: "u1", Method: mfatest.DriverName, Secret: []byte("phone")})))

	app := newTestApp(t)
	Bind(app, "/auth", a)

	m, err := a.MFAMethods().Get(context.Background(), mfatest.DriverName)
	qt.Assert(t, qt.IsNil(err))

	id, _, err := m.BeginVerify(context.Background(), "u1")
	qt.Assert(t, qt.IsNil(err))

	tc := app.TestClient()

	resp, err := tc.PostJSON("/auth/mfa/callback/push", map[string]any{"challenge_id": id, "approved": true},
		tc.WithHeader(mfatest.HeaderCallbackSecret, "hook-secret"))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 204))

	res, err := m.Verify(context.Background(), "u1", id, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.Result, mfa.VerifyApproved))
}

func TestMFACallbackRejectsBadSecretAndUnknownMethod(t *testing.T) {
	a, _ := mfaTestAuth(t, &client.Client{ID: "spa"})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	resp, err := tc.PostJSON("/auth/mfa/callback/push", map[string]any{"challenge_id": "x", "approved": true})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 403))

	// TOTP has no webhook.
	resp2, err := tc.PostJSON("/auth/mfa/callback/totp", map[string]any{})
	defer fasthttp.ReleaseResponse(resp2)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp2.StatusCode(), 404))
}

func TestBindSkipsMFAWithoutStore(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{ID: "spa"})

	app := newTestApp(t)
	h := Bind(app, "/auth", a)
	qt.Check(t, qt.IsNil(h.MFA.Verify))

	resp, err := app.TestClient().Get("/auth/mfa/methods")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 404))
}

func TestDiscoveryAdvertisesACRValues(t *testing.T) {
	a := newTestAuth(t, session.NewMemoryStore(), &client.Client{ID: "spa"})
	a.Config().ACRLevels = []auth.ACRLevelConfig{{Value: "loa1", Level: 1}, {Value: "loa2", Level: 2, RequireMFA: true}}

	app := newTestApp(t)
	Bind(app, "/auth", a)

	resp, err := app.TestClient().Get("/auth/.well-known/openid-configuration")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	doc := decodeJSON[acrDoc](t, resp)
	qt.Check(t, qt.DeepEquals(doc.ACRValuesSupported, []string{"loa1", "loa2"}))
}
