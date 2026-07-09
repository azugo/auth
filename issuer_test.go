package auth

import (
	"testing"

	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
)

func TestIssuerFor(t *testing.T) {
	cfg := validConfig()
	cfg.Issuer = ""

	a, err := New(newApp(t), cfg, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(a.Issuer.URL("https://example.com", ""), "https://example.com"))
	qt.Check(t, qt.Equals(a.Issuer.URL("https://example.com/", "/auth"), "https://example.com/auth"))
	qt.Check(t, qt.Equals(a.Issuer.URL("https://example.com/", "/auth/"), "https://example.com/auth"))

	// Explicit Issuer wins over everything else.
	cfg2 := validConfig()

	a2, err := New(newApp(t), cfg2, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(a2.Issuer.URL("https://example.com", "/auth"), cfg2.Issuer))

	// BaseURL takes precedence over the request-derived base URL.
	cfg3 := validConfig()
	cfg3.Issuer = ""
	cfg3.BaseURL = "https://pinned.example"

	a3, err := New(newApp(t), cfg3, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(a3.Issuer.URL("https://request-derived.example", "/auth"), "https://pinned.example/auth"))
}
