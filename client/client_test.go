package client

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestClientAuthMethodAllowed(t *testing.T) {
	// Empty allowlist permits any method.
	open := &Client{}
	qt.Check(t, qt.IsTrue(open.AuthMethodAllowed(AuthMethodPassword)))
	qt.Check(t, qt.IsTrue(open.AuthMethodAllowed("azure")))

	restricted := &Client{AllowedAuthMethods: []string{AuthMethodPassword}}
	qt.Check(t, qt.IsTrue(restricted.AuthMethodAllowed(AuthMethodPassword)))
	qt.Check(t, qt.IsFalse(restricted.AuthMethodAllowed("azure")))
}

func TestClientGrantTypeAllowed(t *testing.T) {
	c := &Client{GrantTypes: []string{GrantTypePassword}}
	qt.Check(t, qt.IsTrue(c.GrantTypeAllowed(GrantTypePassword)))
	qt.Check(t, qt.IsFalse(c.GrantTypeAllowed("client_credentials")))

	// No GrantTypes registered - nothing is allowed.
	none := &Client{}
	qt.Check(t, qt.IsFalse(none.GrantTypeAllowed(GrantTypePassword)))
}
