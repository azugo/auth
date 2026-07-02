// Package auth is the transport-free coordinator for the azugo authentication library.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/jti"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/core/cache"
	"azugo.io/core/validation"
)

type (
	// UserInfo is the user record returned by a UserProvider.
	UserInfo = contract.UserInfo
	// UserProvider validates credentials and loads user data.
	UserProvider = contract.UserProvider
	// ExternalUserProvider resolves identities for external IdP logins and passwordless authenticators.
	ExternalUserProvider = contract.ExternalUserProvider
	// Registerer is an optional UserProvider extension for registering new accounts.
	Registerer = contract.Registerer
	// PasswordChanger is an optional UserProvider extension for changing a password.
	PasswordChanger = contract.PasswordChanger
	// PasswordResetter is an optional UserProvider extension for resetting a forgotten password.
	PasswordResetter = contract.PasswordResetter
	// ProfileManager is an optional UserProvider extension for user profile data.
	ProfileManager = contract.ProfileManager
	// RegistrationRequest carries the data for a new user registration.
	RegistrationRequest = contract.RegistrationRequest
	// ClaimMapper maps a UserInfo into token / id_token claims.
	ClaimMapper = contract.ClaimMapper
	// ClaimMapperFunc adapts a plain function to the ClaimMapper interface.
	ClaimMapperFunc = contract.ClaimMapperFunc
)

// TxRunner allows to run the multi-write handler sequences so they can be made
// atomic.
type TxRunner interface {
	RunInTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// TransactorFunc adapts a plain function to the TxRunner interface.
type TransactorFunc func(ctx context.Context, fn func(ctx context.Context) error) error

// RunInTx implements TxRunner.
func (f TransactorFunc) RunInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return f(ctx, fn)
}

// Auth is the transport-free authentication service.
type Auth struct {
	cfg      *Configuration
	cache    *cache.Cache
	users    UserProvider
	sessions session.Store
	clients  client.Registry
	jti      jti.Store
	tx       TxRunner
	codec    *token.Codec // seals/opens PASETO tokens; per-instance key cache
}

// Option configures an Auth instance at construction.
type Option func(*Auth)

// JTIStore replaces the default cache-backed CacheStore with a custom jti.Store.
func JTIStore(store jti.Store) Option {
	return func(a *Auth) { a.jti = store }
}

// Transactor to allow to run multi-write handler sequences so they can be made atomic.
func Transactor(t TxRunner) Option {
	return func(a *Auth) { a.tx = t }
}

// New creates an Auth instance.
func New(cfg *Configuration, c *cache.Cache, users UserProvider, sessions session.Store, clients client.Registry, opts ...Option) (*Auth, error) {
	if cfg == nil {
		return nil, errors.New("configuration is required")
	}

	if users == nil {
		return nil, errors.New("user provider is required")
	}

	if sessions == nil {
		return nil, errors.New("session store is required")
	}

	if clients == nil {
		return nil, errors.New("client registry is required")
	}

	// Set defaults if not set
	setDefaults(cfg)

	if err := cfg.Validate(validation.New()); err != nil {
		return nil, fmt.Errorf(" invalid configuration: %w", err)
	}

	a := &Auth{
		cfg:      cfg,
		cache:    c,
		users:    users,
		sessions: sessions,
		clients:  clients,
		codec:    token.NewCodec(cfg),
	}

	for _, opt := range opts {
		opt(a)
	}

	if a.jti == nil {
		if c == nil {
			return nil, errors.New("cache is required for the default JTI store")
		}

		store, err := jti.NewCacheStore(c)
		if err != nil {
			return nil, fmt.Errorf("failed to create JTI store: %w", err)
		}

		a.jti = store
	}

	return a, nil
}

// Users returns the configured user provider.
func (a *Auth) Users() UserProvider {
	return a.users
}

// Sessions returns the configured session store.
func (a *Auth) Sessions() session.Store {
	return a.sessions
}

// Clients returns the configured client registry.
func (a *Auth) Clients() client.Registry {
	return a.clients
}

// JTI returns the configured JTI allowlist store.
func (a *Auth) JTI() jti.Store {
	return a.jti
}

// Config returns the auth Configuration.
func (a *Auth) Config() *Configuration {
	return a.cfg
}

func (a *Auth) runInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if a.tx == nil {
		return fn(ctx)
	}

	return a.tx.RunInTx(ctx, fn)
}

func setDefaults(cfg *Configuration) {
	if cfg.CookieName == "" {
		cfg.CookieName = "__session"
	}

	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = 20 * time.Minute
	}

	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 8 * time.Hour
	}

	if cfg.CodeTTL == 0 {
		cfg.CodeTTL = 60 * time.Second
	}

	if cfg.Throttle.MaxAttempts == 0 {
		cfg.Throttle.MaxAttempts = 5
	}

	if cfg.Throttle.Window == 0 {
		cfg.Throttle.Window = 15 * time.Minute
	}

	if cfg.Throttle.LockoutTTL == 0 {
		cfg.Throttle.LockoutTTL = 15 * time.Minute
	}

	if cfg.Throttle.MFAResendCooldown == 0 {
		cfg.Throttle.MFAResendCooldown = 60 * time.Second
	}

	if cfg.Throttle.MFAMaxResends == 0 {
		cfg.Throttle.MFAMaxResends = 3
	}
}
