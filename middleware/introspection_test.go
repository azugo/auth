package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/client"
	"azugo.io/auth/internal/dpoptest"
	"azugo.io/auth/token"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

const (
	boundToken  = "opaque-bound-token"
	bearerToken = "opaque-bearer-token"
	publicURL   = "https://api.example.com"
)

// introspectionServer answers RFC 7662 introspection for the two known tokens, the bound one
// confirmed by key.
func introspectionServer(t *testing.T, key *dpoptest.Key) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var res auth.IntrospectionResponse

		switch r.FormValue("token") {
		case boundToken:
			res = auth.IntrospectionResponse{Active: true, Subject: "u1", ClientID: "spa", TokenType: "DPoP", Confirmation: &token.Confirmation{JKT: key.JKT}}
		case bearerToken:
			res = auth.IntrospectionResponse{Active: true, Subject: "u1", ClientID: "spa", TokenType: "Bearer"}
		}

		body, err := json.Marshal(res)
		qt.Assert(t, qt.IsNil(err))

		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	return srv
}

func newIntrospectionApp(t *testing.T, a *auth.Auth, endpoint string) *azugo.TestApp {
	t.Helper()

	app := newTestApp(t)
	app.Use(Introspection(a, endpoint, ClientCredentials{ClientID: "rs", Secret: "s3cret"}, NoIntrospectionCache()))
	app.Get("/", func(ctx *azugo.Context) {
		if ctx.User().Authorized() {
			ctx.Text(ctx.User().ID())

			return
		}

		ctx.Text("anonymous")
	})

	return app
}

func TestIntrospectionPinsProofURL(t *testing.T) {
	key := dpoptest.NewKey(t)
	srv := introspectionServer(t, key)

	// The proof's htu is checked against the auth instance's BaseURL, else the request's.
	for name, tt := range map[string]struct {
		base string
		htu  string
		want int
	}{
		"request url":             {"", testURL, 200},
		"pinned url":              {publicURL, publicURL + "/", 200},
		"public url not pinned":   {"", publicURL + "/", 401},
		"request url when pinned": {publicURL, testURL, 401},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			cfg.BaseURL = tt.base
			tc := newIntrospectionApp(t, newTestAuthWithConfig(t, cfg, &client.Client{ID: "spa"}), srv.URL).TestClient()

			resp, err := tc.Get("/", tc.WithHeader("Authorization", "DPoP "+boundToken), tc.WithHeader("DPoP", key.AccessProof(t, "GET", tt.htu, boundToken)))
			defer fasthttp.ReleaseResponse(resp)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(resp.StatusCode(), tt.want))

			if tt.want == 200 {
				qt.Check(t, qt.Equals(string(resp.Body()), "u1"))
			} else {
				qt.Check(t, qt.StringContains(string(resp.Header.Peek("WWW-Authenticate")), `DPoP error="invalid_dpop_proof"`))
			}
		})
	}
}

func TestIntrospectionAudience(t *testing.T) {
	srv := introspectionServer(t, dpoptest.NewKey(t))
	a := newTestAuth(t, &client.Client{ID: "spa"})
	creds := ClientCredentials{ClientID: "rs", Secret: "s3cret"}

	app := newTestApp(t)
	whoami := func(ctx *azugo.Context) {
		if ctx.User().Authorized() {
			ctx.Text(ctx.User().ID())

			return
		}

		ctx.Text("anonymous")
	}

	ga := app.Group("/a")
	ga.Use(Introspection(a, srv.URL, creds, IntrospectionAudience("spa")))
	ga.Get("/", whoami)

	gb := app.Group("/b")
	gb.Use(Introspection(a, srv.URL, creds, IntrospectionAudience("other")))
	gb.Get("/", whoami)

	tc := app.TestClient()

	// Each instance, cache on, accepts only tokens within its own audience.
	for path, want := range map[string]string{"/a/": "u1", "/b/": "anonymous"} {
		for range 2 {
			resp, err := tc.Get(path, tc.WithHeader("Authorization", "Bearer "+bearerToken))
			qt.Assert(t, qt.IsNil(err))
			qt.Check(t, qt.Equals(string(resp.Body()), want), qt.Commentf(path))
			fasthttp.ReleaseResponse(resp)
		}
	}
}

func TestIntrospectionChallengesWithDPoP(t *testing.T) {
	key := dpoptest.NewKey(t)
	srv := introspectionServer(t, key)
	tc := newIntrospectionApp(t, newTestAuth(t, &client.Client{ID: "spa"}), srv.URL).TestClient()

	for name, tt := range map[string]struct {
		opts   []azugo.TestClientOption
		status int
		code   string
	}{
		"bearer":          {[]azugo.TestClientOption{tc.WithHeader("Authorization", "Bearer "+bearerToken)}, 200, ""},
		"no credential":   {nil, 200, ""},
		"bound as bearer": {[]azugo.TestClientOption{tc.WithHeader("Authorization", "Bearer "+boundToken)}, 401, "invalid_token"},
		"unbound as dpop": {[]azugo.TestClientOption{tc.WithHeader("Authorization", "DPoP "+bearerToken), tc.WithHeader("DPoP", key.AccessProof(t, "GET", testURL, bearerToken))}, 401, "invalid_token"},
		"missing proof":   {[]azugo.TestClientOption{tc.WithHeader("Authorization", "DPoP "+boundToken)}, 401, "invalid_dpop_proof"},
		"other key":       {[]azugo.TestClientOption{tc.WithHeader("Authorization", "DPoP "+boundToken), tc.WithHeader("DPoP", dpoptest.NewKey(t).AccessProof(t, "GET", testURL, boundToken))}, 401, "invalid_dpop_proof"},
		"other token":     {[]azugo.TestClientOption{tc.WithHeader("Authorization", "DPoP "+boundToken), tc.WithHeader("DPoP", key.AccessProof(t, "GET", testURL, bearerToken))}, 401, "invalid_dpop_proof"},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := tc.Get("/", tt.opts...)
			defer fasthttp.ReleaseResponse(resp)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(resp.StatusCode(), tt.status))

			if tt.code == "" {
				return
			}

			challenge := string(resp.Header.Peek("WWW-Authenticate"))
			qt.Check(t, qt.IsTrue(strings.HasPrefix(challenge, "DPoP ")))
			qt.Check(t, qt.StringContains(challenge, `error="`+tt.code+`"`))
		})
	}
}
