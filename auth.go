// Package auth is the transport-free coordinator for the azugo authentication library.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/code"
	"azugo.io/auth/contract"
	"azugo.io/auth/event"
	"azugo.io/auth/jti"
	"azugo.io/auth/mfa"
	"azugo.io/auth/provider"
	"azugo.io/auth/reset"
	"azugo.io/auth/session"
	"azugo.io/auth/throttle"
	"azugo.io/auth/token"

	"azugo.io/azugo"
	"azugo.io/core"
	"azugo.io/core/cache"
	"azugo.io/core/validation"
	"go.uber.org/zap"
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
	// PasswordConfig tunes the default password policy.
	PasswordConfig = contract.PasswordConfig
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
	app      *core.App
	config   *Configuration
	users    UserProvider
	sessions session.Store
	clients  client.Registry
	jti      jti.Store
	keys     token.KeyProvider // nil = introspect-only mode, no JWKS/id_token
	codec    *token.Codec      // seals/opens PASETO tokens; per-instance key cache
	codes    code.Store
	// denied deny-lists revoked JWT access-token JTIs (RFC 7009).
	denied jti.DenyList
	// assertions deny-lists already-seen client_assertion JTIs (replay defence).
	assertions jti.DenyList
	throttle   throttle.Throttle
	// extstart bounds how often one caller may start an external IdP round-trip
	extstart throttle.Throttle
	// registrations bounds how many accounts one caller may register
	registrations throttle.Throttle
	events        event.Sink // nil = no audit events

	providers      provider.Registry
	providerClaims ClaimMapper               // app-wide external claim mapper (nil = driver default)
	identities     provider.IdentityStore    // nil = app-managed linking via FindOrCreateUser only
	relink         provider.RelinkAuthorizer // nil = refuse moves
	// State of external IdP redirects
	extstate cache.Instance[externalState]
	// Cache of the IdP id_token per session for federated-logout id_token_hint
	fedIDTokens cache.Instance[string]

	mfaStore   mfa.Store // nil = MFA disabled
	mfaMethods mfa.Registry
	// pending holds the step state of pending sessions, keyed by session ID
	pending cache.Instance[pendingState]
	// enrollments holds in-progress MFA enrollment state, keyed by user ID and method
	enrollments cache.Instance[mfaEnrollment]
	// challenges counts issued MFA and reset challenges per pending flow and method
	challenges cache.Counter
	// resets holds the reset requests in progress; nil unless users is a PasswordResetter
	resets reset.Store
	// resetMethods resolves the ways a user may prove ownership for a reset
	resetMethods reset.Registry
	// passwords accepts or rejects every new password before it reaches users
	passwords contract.PasswordPolicy

	// Cookie provides session cookie attribute helpers.
	Cookie CookieCtx
	// Issuer provides OIDC issuer resolution helpers.
	Issuer IssuerCtx
	// Transaction provides multi-write transaction helpers.
	Transaction TransactionCtx
}

// Option configures an Auth instance at construction.
type Option func(*Auth)

// JTIStore replaces the default cache-backed CacheStore with a custom jti.Store.
func JTIStore(store jti.Store) Option {
	return func(a *Auth) { a.jti = store }
}

// KeyProvider replaces the default ConfigKeyProvider with a custom.
func KeyProvider(p token.KeyProvider) Option {
	return func(a *Auth) { a.keys = p }
}

// CodeStore replaces the default cache-backed authorization-code store with a custom.
func CodeStore(store code.Store) Option {
	return func(a *Auth) { a.codes = store }
}

// Throttle replaces the default ThrottleConfig-driven brute-force guard with a custom.
func Throttle(t throttle.Throttle) Option {
	return func(a *Auth) { a.throttle = t }
}

// Events replaces the default audit event sink. The default writes each event as a
// structured log record via the request logger.
func Events(sink event.Sink) Option {
	return func(a *Auth) { a.events = sink }
}

// Transactor to allow to run multi-write handler sequences so they can be made atomic.
func Transactor(t TxRunner) Option {
	return func(a *Auth) { a.Transaction.tx = t }
}

// ProviderRegistry replaces the default Configuration.Providers-backed external provider
// registry with a custom.
func ProviderRegistry(r provider.Registry) Option {
	return func(a *Auth) { a.providers = r }
}

// ClaimMapping registers a single app-wide claim mapper consulted for every external provider
// that has no per-provider override.
func ClaimMapping(m ClaimMapper) Option {
	return func(a *Auth) { a.providerClaims = m }
}

// IdentityStore enables library-owned account linking of external identities.
func IdentityStore(s provider.IdentityStore) Option {
	return func(a *Auth) { a.identities = s }
}

// RelinkPolicy permits moving an already-linked external identity to another user under the
// authorizer's rules. Without it, conflicts are refused.
func RelinkPolicy(p provider.RelinkAuthorizer) Option {
	return func(a *Auth) { a.relink = p }
}

// MFAStore enables MFA. Without it no MFA endpoint is mounted, a client whose MFAPolicy is
// required refuses every login and optional is inert.
func MFAStore(s mfa.Store) Option {
	return func(a *Auth) { a.mfaStore = s }
}

// MFARegistry replaces the default Configuration.MFAMethods-backed method registry with a
// custom.
func MFARegistry(r mfa.Registry) Option {
	return func(a *Auth) { a.mfaMethods = r }
}

// PasswordResetStore replaces the default cache-backed store of reset requests with a custom.
func PasswordResetStore(s reset.Store) Option {
	return func(a *Auth) { a.resets = s }
}

// PasswordResetRegistry replaces the default Configuration.PasswordResetMethods-backed method
// registry with a custom, e.g. reset.Methods for methods built in code.
func PasswordResetRegistry(r reset.Registry) Option {
	return func(a *Auth) { a.resetMethods = r }
}

// PasswordPolicy replaces the default Configuration.Password-driven policy with a custom.
func PasswordPolicy(p contract.PasswordPolicy) Option {
	return func(a *Auth) { a.passwords = p }
}

// CookieScopeToBasePath makes the default session cookie Path resolve to the app's base path.
func CookieScopeToBasePath() Option {
	return func(a *Auth) {
		a.Cookie.scopeToBasePath = true
	}
}

// New creates an Auth instance.
func New(app *core.App, config *Configuration, users UserProvider, sessions session.Store, clients client.Registry, opts ...Option) (*Auth, error) {
	if app == nil {
		return nil, errors.New("app is required")
	}

	if config == nil {
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
	setDefaults(config)

	if err := config.Validate(validation.New()); err != nil {
		return nil, fmt.Errorf(" invalid configuration: %w", err)
	}

	a := &Auth{
		app:      app,
		config:   config,
		users:    users,
		sessions: sessions,
		clients:  clients,
		codec:    token.NewCodec(config),
	}

	a.Cookie.config = config
	a.Cookie.app = app
	a.Issuer.config = config

	for _, opt := range opts {
		opt(a)
	}

	if a.jti == nil {
		store, err := jti.NewCacheStore(app.Cache())
		if err != nil {
			return nil, fmt.Errorf("failed to create JTI store: %w", err)
		}

		a.jti = store
	}

	if a.keys == nil && config.Keys != nil {
		keys, err := token.NewConfigKeyProvider(config.Keys)
		if err != nil {
			return nil, fmt.Errorf("failed to create key provider: %w", err)
		}

		a.keys = keys
	}

	if a.codes == nil {
		store, err := code.NewCacheStore(app.Cache(), config.AccessTokenTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to create authorization code store: %w", err)
		}

		a.codes = store
	}

	denied, err := jti.NewCacheDenyList(app.Cache(), "auth:jwt:denied")
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT deny-list: %w", err)
	}

	a.denied = denied

	assertions, err := jti.NewCacheDenyList(app.Cache(), "auth:assertion:seen")
	if err != nil {
		return nil, fmt.Errorf("failed to create assertion replay list: %w", err)
	}

	a.assertions = assertions

	if a.throttle == nil {
		t, err := throttle.New(app.Cache(), &config.Throttle)
		if err != nil {
			return nil, fmt.Errorf("failed to create throttle: %w", err)
		}

		a.throttle = t
	}

	extstart, err := throttle.NewLimit(app.Cache(), "auth:extstart", config.Throttle.ExternalStartMax, config.Throttle.Window)
	if err != nil {
		return nil, fmt.Errorf("failed to create external start throttle: %w", err)
	}

	a.extstart = extstart

	registrations, err := throttle.NewLimit(app.Cache(), "auth:register", config.Throttle.RegistrationMax, config.Throttle.Window)
	if err != nil {
		return nil, fmt.Errorf("failed to create registration throttle: %w", err)
	}

	a.registrations = registrations

	if a.events == nil {
		a.events = &logEventSink{auth: a}
	}

	if a.passwords == nil {
		a.passwords = NewPasswordPolicy(&config.Password)
	}

	if a.providers == nil {
		a.providers = provider.NewConfigRegistry(config)
	}

	if _, ok := users.(ExternalUserProvider); !ok && a.identities == nil && len(config.Providers) > 0 {
		return nil, errors.New("external providers require a user provider implementing ExternalUserProvider or an identity store")
	}

	// Best-effort check for provider misconfiguration surfaces early
	if p, ok := a.providers.(provider.Prewarmer); ok {
		if err := p.Prewarm(context.Background()); err != nil {
			a.Log(a.app.BackgroundContext()).Warn("failed to pre-warm external providers", zap.Error(err))
		}
	}

	extstate, err := cache.Create[externalState](app.Cache(), "auth:extstate")
	if err != nil {
		return nil, fmt.Errorf("failed to create external state store: %w", err)
	}

	a.extstate = extstate

	fedIDTokens, err := cache.Create[string](app.Cache(), "auth:fedidt")
	if err != nil {
		return nil, fmt.Errorf("failed to create federated id_token store: %w", err)
	}

	a.fedIDTokens = fedIDTokens

	pending, err := cache.Create[pendingState](app.Cache(), "auth:pending")
	if err != nil {
		return nil, fmt.Errorf("failed to create pending step store: %w", err)
	}

	a.pending = pending

	if _, ok := users.(PasswordResetter); ok {
		if a.resets == nil {
			resets, err := reset.NewCacheStore(app.Cache())
			if err != nil {
				return nil, fmt.Errorf("failed to create password reset store: %w", err)
			}

			a.resets = resets
		}

		if a.resetMethods == nil {
			a.resetMethods = reset.NewConfigRegistry(config)
		}

		names, err := a.resetMethods.Names(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to list password reset methods: %w", err)
		}

		if len(names) == 0 {
			return nil, errors.New("a PasswordResetter user provider requires at least one password reset method")
		}
	}

	if a.mfaStore != nil {
		if a.mfaMethods == nil {
			a.mfaMethods = mfa.NewConfigRegistry(config, a.mfaStore)
		}

		enrollments, err := cache.Create[mfaEnrollment](app.Cache(), "auth:mfa:enroll")
		if err != nil {
			return nil, fmt.Errorf("failed to create MFA enrollment store: %w", err)
		}

		a.enrollments = enrollments
	}

	challenges, err := cache.CreateCounter(app.Cache(), "auth:challenge")
	if err != nil {
		return nil, fmt.Errorf("failed to create challenge counter: %w", err)
	}

	a.challenges = challenges

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

// Keys returns the configured key provider, or nil in introspect-only mode.
func (a *Auth) Keys() token.KeyProvider {
	return a.keys
}

// Codes returns the configured authorization-code store.
func (a *Auth) Codes() code.Store {
	return a.codes
}

// Providers returns the configured external provider registry.
func (a *Auth) Providers() provider.Registry {
	return a.providers
}

// Identities returns the configured external identity link store, or nil when account linking
// is app-managed.
func (a *Auth) Identities() provider.IdentityStore {
	return a.identities
}

// MFA returns the configured MFA enrollment store, or nil when MFA is disabled.
func (a *Auth) MFA() mfa.Store {
	return a.mfaStore
}

// PasswordResets returns the configured store of reset requests, or nil when the user provider
// is not a PasswordResetter.
func (a *Auth) PasswordResets() reset.Store {
	return a.resets
}

// PasswordResetMethods returns the configured reset method registry, or nil when the user
// provider is not a PasswordResetter.
func (a *Auth) PasswordResetMethods() reset.Registry {
	return a.resetMethods
}

// PasswordPolicy returns the configured password policy.
func (a *Auth) PasswordPolicy() contract.PasswordPolicy {
	return a.passwords
}

// MFAMethods returns the configured MFA method registry, or nil when MFA is disabled.
func (a *Auth) MFAMethods() mfa.Registry {
	return a.mfaMethods
}

// emit sends e to the configured event sink, stamping At.
func (a *Auth) emit(ctx context.Context, e event.Event) {
	if a.events == nil {
		return
	}

	e.At = time.Now()
	a.events.Emit(ctx, e)
}

// Config returns the auth Configuration.
func (a *Auth) Config() *Configuration {
	return a.config
}

// Log returns the "auth" logger, request-scoped when ctx carries a request.
func (a *Auth) Log(ctx context.Context) *zap.Logger {
	log := a.app.Log()
	if actx := azugo.RequestContext(ctx); actx != nil {
		log = actx.Log()
	}

	return log.Named("auth")
}

func setDefaults(cfg *Configuration) {
	if cfg.CookieName == "" {
		cfg.CookieName = "session"
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

	if cfg.ExternalStateTTL == 0 {
		cfg.ExternalStateTTL = 15 * time.Minute
	}

	if cfg.PasswordResetTTL == 0 {
		cfg.PasswordResetTTL = time.Hour
	}

	if cfg.Password.MinLength == 0 {
		cfg.Password.MinLength = 8
	}

	if cfg.Password.MaxLength == 0 {
		cfg.Password.MaxLength = 128
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

	if cfg.Throttle.ExternalStartMax == 0 {
		cfg.Throttle.ExternalStartMax = 300
	}

	if cfg.Throttle.RegistrationMax == 0 {
		cfg.Throttle.RegistrationMax = 20
	}
}
