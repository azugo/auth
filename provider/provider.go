// Package provider defines the external identity-provider driver contracts and the registry
// that resolves configured providers per request.
package provider

import (
	"context"
	"fmt"
	"sync"
	"time"

	"azugo.io/auth/contract"
)

// Provider is external IdP instance.
type Provider interface {
	// AuthURL returns the provider's authorization URL.
	AuthURL(ctx context.Context, state, nonce, codeChallenge string) (string, error)
	// Exchange trades an authorization code (+ PKCE verifier) for provider tokens.
	//
	// MUST fully validate the returned id_token (signature/iss/aud/exp/nonce) before
	// returning RawClaims.
	Exchange(ctx context.Context, code, codeVerifier, nonce string) (*Tokens, error)
}

// Tokens is the validated result of an authorization-code exchange with the IdP.
type Tokens struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
	// RawClaims holds the id_token claims.
	RawClaims map[string]any
}

// Logouter is an optional Provider extension for IdPs that support RP-initiated logout.
type Logouter interface {
	// LogoutURL builds the IdP end-session URL.
	LogoutURL(ctx context.Context, idTokenHint, state, postLogoutRedirectURI string) (string, error)
}

// Driver is implemented by each external IdP package and registered via Register.
type Driver interface {
	// Open creates a Provider from the configuration entry.
	Open(cfg *contract.ExternalProviderConfig) (Provider, error)
	// DefaultClaimMapper returns the driver's built-in claim mapper.
	DefaultClaimMapper() ClaimMapper
}

var (
	driversMu sync.RWMutex
	drivers   = make(map[string]Driver)
)

// Register makes a Driver available under name.
//
// Panics on a nil or duplicate registration.
func Register(name string, d Driver) {
	driversMu.Lock()
	defer driversMu.Unlock()

	if d == nil {
		panic("provider: Register driver is nil")
	}

	if _, dup := drivers[name]; dup {
		panic("provider: Register called twice for driver " + name)
	}

	drivers[name] = d
}

func driver(name string) (Driver, error) {
	driversMu.RLock()
	defer driversMu.RUnlock()

	d, ok := drivers[name]
	if !ok {
		return nil, fmt.Errorf("provider: unknown driver %q", name)
	}

	return d, nil
}

// DefaultClaimMapper returns the registered driver's built-in ClaimMapper, so an app-wide
// mapper can wrap it.
func DefaultClaimMapper(name string) (ClaimMapper, error) {
	d, err := driver(name)
	if err != nil {
		return nil, err
	}

	return d.DefaultClaimMapper(), nil
}
