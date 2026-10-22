package routes

import (
	"context"
	"slices"
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

// tenantStep asks for a tenant once per login and switches between tenants.
type tenantStep struct{}

var tenants = []string{"acme", "globex"}

func (tenantStep) Name() string {
	return "tenant"
}

func (tenantStep) Required(_ context.Context, s *session.Session, _ auth.UserInfo) (bool, error) {
	return s.Context["tenant"] == nil, nil
}

func (tenantStep) Prompt(context.Context, *session.Session, auth.UserInfo) (auth.StepPrompt, error) {
	return auth.StepPrompt{Interaction: "select_tenant", Data: map[string]any{"tenants": tenants}}, nil
}

func (s tenantStep) Resolve(ctx context.Context, sess *session.Session, _ auth.UserInfo, payload []byte) (auth.StepResult, error) {
	var in map[string]any
	if err := json.Unmarshal(payload, &in); err != nil {
		return auth.StepResult{}, err
	}

	if _, err := s.Switch(ctx, sess, in); err != nil {
		return auth.StepResult{}, nil //nolint:nilerr
	}

	return auth.StepResult{Done: true}, nil
}

func (tenantStep) Switch(_ context.Context, sess *session.Session, selection map[string]any) (auth.SwitchMode, error) {
	tenant, _ := selection["tenant"].(string)
	if !slices.Contains(tenants, tenant) {
		return auth.SwitchRotate, auth.ErrInvalidSelection
	}

	sess.Context["tenant"] = tenant
	// A careless step copying input over a standard claim.
	sess.Context["email"] = "mallory@example.com"
	sess.Context["email_verified"] = true

	return auth.SwitchRotate, nil
}

type stepBody struct {
	Status      string         `json:"status"`
	Step        string         `json:"step"`
	StepToken   string         `json:"step_token"`
	Interaction string         `json:"interaction"`
	Data        map[string]any `json:"data"`
}

func TestStepAndSwitchRoutes(t *testing.T) {
	a := newTestAuthWithOpts(t, session.NewMemoryStore(), []auth.Option{auth.LoginSteps(tenantStep{})}, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()

	resp, err := tc.PostForm("/auth/token", map[string]any{"grant_type": "password", "client_id": "spa", "username": "alice", "password": "right"})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 202))

	var pending stepBody
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &pending)))
	qt.Check(t, qt.Equals(pending.Status, string(session.StatusPendingStep)))
	qt.Check(t, qt.Equals(pending.Step, "tenant"))
	qt.Check(t, qt.Equals(pending.Interaction, "select_tenant"))

	stepAuth := tc.WithHeader("Authorization", "Bearer "+pending.StepToken)

	unknown, err := tc.PostJSON("/auth/steps/role", map[string]any{}, stepAuth)
	defer fasthttp.ReleaseResponse(unknown)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(unknown.StatusCode(), 404))

	resolved, err := tc.PostJSON("/auth/steps/tenant", map[string]any{"tenant": "acme"}, stepAuth)
	defer fasthttp.ReleaseResponse(resolved)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resolved.StatusCode(), 200))

	var tok tokenBody
	qt.Assert(t, qt.IsNil(json.Unmarshal(resolved.Body(), &tok)))

	qt.Check(t, qt.Equals(userinfoTenant(t, tc, tok.AccessToken), "acme"))

	switched, err := tc.PostJSON("/auth/session/switch", map[string]any{"tenant": "globex"}, tc.WithHeader("Authorization", "Bearer "+tok.AccessToken))
	defer fasthttp.ReleaseResponse(switched)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(switched.StatusCode(), 200))

	var next tokenBody
	qt.Assert(t, qt.IsNil(json.Unmarshal(switched.Body(), &next)))
	qt.Check(t, qt.Equals(userinfoTenant(t, tc, next.AccessToken), "globex"))
}

func userinfoTenant(t *testing.T, tc *azugo.TestClient, accessToken string) string {
	t.Helper()

	resp, err := tc.Get("/auth/userinfo", tc.WithHeader("Authorization", "Bearer "+accessToken))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	var body struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Tenant        string `json:"tenant"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &body)))
	qt.Check(t, qt.Equals(body.Subject, "u1"))
	qt.Check(t, qt.Equals(body.Email, "alice@example.com"))
	qt.Assert(t, qt.IsNotNil(body.EmailVerified))
	qt.Check(t, qt.IsFalse(*body.EmailVerified))

	return body.Tenant
}

func TestSwitchRouteRefusesCrossSiteCookie(t *testing.T) {
	a := newTestAuthWithOpts(t, session.NewMemoryStore(), []auth.Option{auth.LoginSteps(tenantStep{})}, &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeCookie,
	})

	pending, err := a.Login(context.Background(), auth.LoginRequest{Credentials: auth.ClientCredentials{ClientID: "ssr"}, Username: "alice", Password: "right"})
	qt.Assert(t, qt.IsNil(err))

	active, err := a.ResolveStep(context.Background(), auth.StepRequest{Token: pending.StepToken, Name: "tenant", Payload: []byte(`{"tenant":"acme"}`)})
	qt.Assert(t, qt.IsNil(err))

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	cookie := tc.WithCookie(a.Config().CookieName, active.Cookie.Value)

	crossSite, err := tc.PostForm("/auth/session/switch", map[string]any{"tenant": "globex"}, cookie, tc.WithHeader("Sec-Fetch-Site", "cross-site"))
	defer fasthttp.ReleaseResponse(crossSite)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(crossSite.StatusCode(), 403))

	// Neither Fetch Metadata nor Origin proves where the request came from.
	unknown, err := tc.PostForm("/auth/session/switch", map[string]any{"tenant": "globex"}, cookie)
	defer fasthttp.ReleaseResponse(unknown)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(unknown.StatusCode(), 403))

	sameSite, err := tc.PostForm("/auth/session/switch", map[string]any{"tenant": "globex"}, cookie, tc.WithHeader("Sec-Fetch-Site", "same-origin"))
	defer fasthttp.ReleaseResponse(sameSite)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sameSite.StatusCode(), 204))
}

func TestStepRouteRefusesCrossSiteCookie(t *testing.T) {
	a := newTestAuthWithOpts(t, session.NewMemoryStore(), []auth.Option{auth.LoginSteps(tenantStep{})}, &client.Client{
		ID: "ssr", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeCookie,
	})

	pending, err := a.Login(context.Background(), auth.LoginRequest{Credentials: auth.ClientCredentials{ClientID: "ssr"}, Username: "alice", Password: "right"})
	qt.Assert(t, qt.IsNil(err))

	app := newTestApp(t)
	Bind(app, "/auth", a)

	tc := app.TestClient()
	cookie := tc.WithCookie(a.Config().CookieName, pending.Cookie.Value)

	crossSite, err := tc.PostJSON("/auth/steps/tenant", map[string]any{"tenant": "acme"}, cookie, tc.WithHeader("Sec-Fetch-Site", "cross-site"))
	defer fasthttp.ReleaseResponse(crossSite)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(crossSite.StatusCode(), 403))

	sameSite, err := tc.PostJSON("/auth/steps/tenant", map[string]any{"tenant": "acme"}, cookie, tc.WithHeader("Sec-Fetch-Site", "same-origin"))
	defer fasthttp.ReleaseResponse(sameSite)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sameSite.StatusCode(), 204))
}
