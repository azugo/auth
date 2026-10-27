package middleware

import (
	"context"
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/apikey"
	"azugo.io/auth/client"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestRequireSubject(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	}, auth.APIKeyStore(apikey.NewMemoryStore()))

	// A webhook key names no actions: receiving the webhook is all a webhook does.
	key, err := a.IssueSubjectAPIKey(context.Background(), auth.SubjectAPIKeyRequest{Type: "webhook", Identifier: "42", ClientID: "spa"})
	qt.Assert(t, qt.IsNil(err))

	app := newTestApp(t)
	app.Use(Auth(a, APIKey()))
	app.Post("/webhooks/{id}", RequireSubject("webhook", "id")(func(ctx *azugo.Context) {
		ctx.StatusCode(204)
	}))
	app.Post("/webhooks/{id}/replay", RequireAction("webhook", "id", "replay")(func(ctx *azugo.Context) {
		ctx.StatusCode(204)
	}))

	tc := app.TestClient()

	for name, tt := range map[string]struct {
		path   string
		status int
	}{
		"its object":     {"/webhooks/42", 204},
		"another object": {"/webhooks/43", 403},
		"a named action": {"/webhooks/42/replay", 403},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := tc.Post(tt.path, nil, tc.WithHeader("Authorization", "Bearer "+key.Token))
			defer fasthttp.ReleaseResponse(resp)
			qt.Assert(t, qt.IsNil(err))
			qt.Check(t, qt.Equals(resp.StatusCode(), tt.status))
		})
	}

	qt.Check(t, qt.PanicMatches(func() { RequireSubject("", "id") }, "middleware.RequireSubject: .*"))
	qt.Check(t, qt.PanicMatches(func() { RequireSubject("webhook", "") }, "middleware.RequireSubject: .*"))
}

func TestRequireActionNeedsItsArguments(t *testing.T) {
	for name, args := range map[string][3]string{
		"type":   {"", "id", "deploy"},
		"param":  {"deployment", "", "deploy"},
		"action": {"deployment", "id", ""},
	} {
		qt.Check(t, qt.PanicMatches(func() { RequireAction(args[0], args[1], args[2]) }, "middleware.RequireAction: .*"), qt.Commentf(name))
	}
}

func TestRequireAction(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	}, auth.APIKeyStore(apikey.NewMemoryStore()))

	key, err := a.IssueSubjectAPIKey(context.Background(), auth.SubjectAPIKeyRequest{Type: "deployment", Identifier: "42", Actions: []string{"deploy"}, ClientID: "spa"})
	qt.Assert(t, qt.IsNil(err))

	user, err := a.Login(context.Background(), auth.LoginRequest{Credentials: auth.ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "irrelevant"})
	qt.Assert(t, qt.IsNil(err))

	app := newTestApp(t)
	app.Use(Auth(a, APIKey()))
	app.Post("/deployments/{id}/deploy", RequireAction("deployment", "id", "deploy")(func(ctx *azugo.Context) {
		ctx.StatusCode(204)
	}))

	tc := app.TestClient()

	for name, tt := range map[string]struct {
		path   string
		token  string
		status int
	}{
		"its object":     {"/deployments/42/deploy", key.Token, 204},
		"another object": {"/deployments/43/deploy", key.Token, 403},
		"a user":         {"/deployments/42/deploy", user.AccessToken, 403},
		"anonymous":      {"/deployments/42/deploy", "", 403},
	} {
		t.Run(name, func(t *testing.T) {
			var opts []azugo.TestClientOption
			if tt.token != "" {
				opts = append(opts, tc.WithHeader("Authorization", "Bearer "+tt.token))
			}

			resp, err := tc.Post(tt.path, nil, opts...)
			defer fasthttp.ReleaseResponse(resp)
			qt.Assert(t, qt.IsNil(err))
			qt.Check(t, qt.Equals(resp.StatusCode(), tt.status))
		})
	}
}
