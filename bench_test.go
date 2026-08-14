package auth

import (
	"context"
	"testing"

	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"azugo.io/core"
	"azugo.io/core/config"
)

func benchAuth(b *testing.B) *Auth {
	b.Helper()

	app := core.New()

	conf := config.New()
	if err := conf.Load(nil, conf, string(app.Env())); err != nil {
		b.Fatal(err)
	}

	app.SetConfig(nil, conf)
	b.Cleanup(app.Stop)

	cfg := validConfig()
	cfg.LogoutInvalidatesCookie = true

	users := fakeUsers{
		users:     map[string]UserInfo{"alice": {ID: "u1", Name: "Alice", Scope: "openid profile"}},
		passwords: map[string]string{"alice": "secret123"},
	}

	a, err := New(app, cfg, users, session.NewMemoryStore(), client.NewMemoryRegistry(portalClient()))
	if err != nil {
		b.Fatal(err)
	}

	return a
}

func BenchmarkLogin(b *testing.B) {
	a := benchAuth(b)

	b.ReportAllocs()

	for b.Loop() {
		if _, err := a.Login(context.Background(), LoginRequest{
			ClientID: "spa", Username: "alice", Password: "secret123", IP: "203.0.113.9",
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIntrospectToken(b *testing.B) {
	a := benchAuth(b)

	res, err := a.Login(context.Background(), LoginRequest{
		ClientID: "spa", Username: "alice", Password: "secret123",
	})
	if err != nil {
		b.Fatal(err)
	}

	settle()

	b.ReportAllocs()

	for b.Loop() {
		if _, _, err := a.IntrospectToken(context.Background(), res.AccessToken); err != nil {
			b.Fatal(err)
		}
	}
}
