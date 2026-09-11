package contract

import (
	"encoding/pem"
	"os"
	"time"

	"azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration is the authentication configuration section.
type Configuration struct {
	Secret string `mapstructure:"secret" validate:"required,min=32"`
	// FallbackSecrets holds previous PASETO local secrets, kept for decryption/verification only,
	// enabling zero-downtime rotation of Secret. New tokens are always sealed with Secret;
	// decryption falls back to this.
	FallbackSecrets []string `mapstructure:"fallback_secrets"`
	// Secure pins the cookie Secure flag, defaults to secure.
	Secure *bool `mapstructure:"secure"`
	// SameSite pins the cookie SameSite mode, defaults to strict.
	SameSite   string `mapstructure:"same_site" validate:"omitempty,oneof=strict lax none"`
	CookieName string `mapstructure:"cookie_name"` // default: "__session"
	CookiePath string `mapstructure:"cookie_path"` // default: base path + auth mount prefix (see CookieCtx.PathFor)
	// LogoutInvalidatesCookie makes logout authoritative server-side (session + JTI revoked).
	// Default true; only disable if a shared cookie must survive a single app's logout.
	LogoutInvalidatesCookie bool          `mapstructure:"logout_invalidates_cookie"`
	AccessTokenTTL          time.Duration `mapstructure:"access_token_ttl" validate:"required"` // default: 20m
	SessionTTL              time.Duration `mapstructure:"session_ttl"      validate:"required"` // default: 8h
	CodeTTL                 time.Duration `mapstructure:"code_ttl"`                             // authorization-code lifetime; default: 60s
	// ExternalStateTTL bounds one external IdP round-trip, from redirect to callback.
	ExternalStateTTL time.Duration `mapstructure:"external_state_ttl"`
	// ClockSkew is the leeway allowed on external id_token time claims, inherited by every
	// provider that does not set its own. Default 1m; keep it under 2m.
	ClockSkew time.Duration `mapstructure:"clock_skew"`
	// BaseURL pins the public base URL used to resolve the issuer and the default cookie
	// path instead of deriving them from the incoming request (proxies, split origin).
	BaseURL string `mapstructure:"base_url" validate:"omitempty,url"`
	// Issuer is the OIDC issuer identifier (iss claim, discovery document base).
	Issuer string `mapstructure:"issuer" validate:"omitempty,url"`
	// Keys is the JWT/JWKS signing key set. Nil = introspect-only mode (no JWKS endpoint,
	// no id_token issuance); supply it (or the KeyProvider() option) to enable JWT tokens.
	Keys           *KeySetConfig            `mapstructure:"keys"           validate:"omitempty"`
	Providers      []ExternalProviderConfig `mapstructure:"providers"      validate:"omitempty,dive"`
	Authenticators []AuthenticatorConfig    `mapstructure:"authenticators" validate:"omitempty,dive"` // passwordless primary methods
	ACRLevels      []ACRLevelConfig         `mapstructure:"acr_levels"     validate:"omitempty,dive"` // trust ladder
	Throttle       ThrottleConfig           `mapstructure:"throttle"`                                 // brute-force / lockout tuning
}

// AuthenticatorConfig configures one passwordless primary-auth driver instance (passkey,
// magic-link, …). Resolved dynamically per request against the live slice, like Providers.
type AuthenticatorConfig struct {
	Name        string            `mapstructure:"name"`   // method name used in URLs: /authn/{name}/* and in AMR
	Driver      string            `mapstructure:"driver"` // registered authenticator driver, e.g. "passkey"
	Config      map[string]string `mapstructure:"config"` // driver-specific options
	ClaimMapper ClaimMapper       `mapstructure:"-"`      // optional per-method override; set in code
}

// ThrottleConfig tunes the default cache-backed lockout guard applied to credential
// endpoints.
type ThrottleConfig struct {
	Enabled bool `mapstructure:"enabled"` // default: true
	// MaxAttempts/Window/LockoutTTL are required (non-zero) only when Enabled is set.
	MaxAttempts int           `mapstructure:"max_attempts" validate:"required_with=Enabled"` // default: 5
	Window      time.Duration `mapstructure:"window"       validate:"required_with=Enabled"` // default: 15m
	LockoutTTL  time.Duration `mapstructure:"lockout_ttl"  validate:"required_with=Enabled"` // default: 15m
	// MFA code resend (POST /mfa/resend), enforced independently of the verify lockout.
	MFAResendCooldown time.Duration `mapstructure:"mfa_resend_cooldown"` // default: 60s
	MFAMaxResends     int           `mapstructure:"mfa_max_resends"`     // default: 3
}

// ACRLevelConfig defines one authentication context class (Level of Assurance). Levels form
// an ordered ladder via Level: satisfying a higher level also satisfies every lower one.
type ACRLevelConfig struct {
	Value       string   `mapstructure:"value"        validate:"required"` // acr string, e.g. "loa1"
	Level       int      `mapstructure:"level"        validate:"required"` // ordinal rank; higher = stronger
	AuthMethods []string `mapstructure:"auth_methods"`                     // permitted primary methods (empty = any)
	RequireMFA  bool     `mapstructure:"require_mfa"`                      // session must have passed MFA
	MFAMethods  []string `mapstructure:"mfa_methods"`                      // permitted MFA methods (empty = any enrolled)
	// MFASatisfiedByAMR lists amr values that, if already present from the PRIMARY method,
	// satisfy RequireMFA without prompting a separate factor.
	MFASatisfiedByAMR []string `mapstructure:"mfa_satisfied_by_amr"`
	AMR               []string `mapstructure:"amr"` // amr values recorded when satisfied (optional)
}

// KeySetConfig holds the signing key set for JWT/JWKS operations. Primary is the default
// signing key; Signing keys offer alternative algorithms (one key per algorithm) for clients
// that register a different id_token_signed_response_alg; Secondary keys verify only (in
// order).
type KeySetConfig struct {
	Primary   KeyConfig   `mapstructure:"primary"   validate:"required"`
	Signing   []KeyConfig `mapstructure:"signing"   validate:"omitempty,dive"`
	Secondary []KeyConfig `mapstructure:"secondary" validate:"omitempty,dive"`
}

// KeyConfig describes one asymmetric key pair or certificate.
type KeyConfig struct {
	// ID is the key ID (kid) included in issued JWTs and the JWKS document; unique per set.
	// Defaults to the RFC 7638 JWK Thumbprint of the public key when unset.
	ID string `mapstructure:"id"`
	// Algorithm is RS256, RS384, RS512, ES256, ES384 or ES512.
	Algorithm string `mapstructure:"algorithm" validate:"omitempty,oneof=RS256 RS384 RS512 ES256 ES384 ES512"`
	// PrivateKey is a PEM-encoded private key.
	PrivateKey string `mapstructure:"private_key"`
	// PublicKey is a PEM-encoded public key or certificate.
	PublicKey string `mapstructure:"public_key"`
}

// ExternalProviderConfig configures one external IdP driver instance.
type ExternalProviderConfig struct {
	Name         string `mapstructure:"name"`   // identifier used in URLs: /external/{name}/*
	Driver       string `mapstructure:"driver"` // registered driver name, e.g. "azure"
	ClientID     string `mapstructure:"client_id"      validate:"required"`
	ClientSecret string `mapstructure:"client_secret"` // loaded via LoadRemoteSecret
	RedirectURL  string `mapstructure:"redirect_url"   validate:"required,url"`
	Scopes       []string
	// LogoutAfterAuth is the "no-SSO" mode: RP-initiate logout at the IdP immediately after a
	// successful login and finalize the local session only on the logout callback.
	LogoutAfterAuth bool `mapstructure:"logout_after_auth"`
	// ClockSkew pins the leeway allowed on this provider's id_token time claims, nil inherits
	// Configuration.ClockSkew and zero validates strictly. The registry resolves it before
	// opening a driver, so drivers see it set.
	ClockSkew   *time.Duration    `mapstructure:"clock_skew"`
	Config      map[string]string `mapstructure:"config"` // driver-specific extra options
	ClaimMapper ClaimMapper       `mapstructure:"-"`
}

// EffectiveClockSkew returns the resolved id_token leeway, treating an unresolved nil as
// strict.
func (e *ExternalProviderConfig) EffectiveClockSkew() time.Duration {
	if e.ClockSkew == nil {
		return 0
	}

	return *e.ClockSkew
}

// Bind registers defaults and environment variable bindings for the auth configuration
// section under the given prefix.
func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	secret, _ := config.LoadRemoteSecret("AUTH_SECRET")

	v.SetDefault(prefix+".secret", secret)
	v.SetDefault(prefix+".cookie_name", "__session")
	v.SetDefault(prefix+".logout_invalidates_cookie", true)
	v.SetDefault(prefix+".access_token_ttl", 20*time.Minute)
	v.SetDefault(prefix+".session_ttl", 8*time.Hour)
	v.SetDefault(prefix+".code_ttl", 60*time.Second)
	v.SetDefault(prefix+".external_state_ttl", 15*time.Minute)
	v.SetDefault(prefix+".clock_skew", time.Minute)
	v.SetDefault(prefix+".throttle.enabled", true)
	v.SetDefault(prefix+".throttle.max_attempts", 5)
	v.SetDefault(prefix+".throttle.window", 15*time.Minute)
	v.SetDefault(prefix+".throttle.lockout_ttl", 15*time.Minute)
	v.SetDefault(prefix+".throttle.mfa_resend_cooldown", 60*time.Second)
	v.SetDefault(prefix+".throttle.mfa_max_resends", 3)

	_ = v.BindEnv(prefix+".secret", "AUTH_SECRET")
	_ = v.BindEnv(prefix+".secure", "AUTH_SECURE")
	_ = v.BindEnv(prefix+".same_site", "AUTH_SAME_SITE")
	_ = v.BindEnv(prefix+".cookie_name", "AUTH_COOKIE_NAME")
	_ = v.BindEnv(prefix+".cookie_path", "AUTH_COOKIE_PATH")
	_ = v.BindEnv(prefix+".logout_invalidates_cookie", "AUTH_LOGOUT_INVALIDATES_COOKIE")
	_ = v.BindEnv(prefix+".access_token_ttl", "AUTH_ACCESS_TOKEN_TTL")
	_ = v.BindEnv(prefix+".session_ttl", "AUTH_SESSION_TTL")
	_ = v.BindEnv(prefix+".code_ttl", "AUTH_CODE_TTL")
	_ = v.BindEnv(prefix+".external_state_ttl", "AUTH_EXTERNAL_STATE_TTL")
	_ = v.BindEnv(prefix+".clock_skew", "AUTH_CLOCK_SKEW")
	_ = v.BindEnv(prefix+".base_url", "AUTH_BASE_URL")
	_ = v.BindEnv(prefix+".issuer", "AUTH_ISSUER")
	_ = v.BindEnv(prefix+".throttle.enabled", "AUTH_THROTTLE_ENABLED")
	_ = v.BindEnv(prefix+".throttle.max_attempts", "AUTH_THROTTLE_MAX_ATTEMPTS")
	_ = v.BindEnv(prefix+".throttle.window", "AUTH_THROTTLE_WINDOW")
	_ = v.BindEnv(prefix+".throttle.lockout_ttl", "AUTH_THROTTLE_LOCKOUT_TTL")
	_ = v.BindEnv(prefix+".throttle.mfa_resend_cooldown", "AUTH_THROTTLE_MFA_RESEND_COOLDOWN")
	_ = v.BindEnv(prefix+".throttle.mfa_max_resends", "AUTH_THROTTLE_MFA_MAX_RESENDS")

	// Load primary key from remote secret
	if primaryKey, _ := config.LoadRemoteSecret("AUTH_KEYS_PRIMARY"); primaryKey != "" {
		v.SetDefault(prefix+".keys.primary.private_key", primaryKey)
	}

	// Load additional signing key(s) from remote secret.
	signingKeys := os.Getenv("AUTH_KEYS_SIGNING")
	if signingKeys == "" {
		signingKeys, _ = config.LoadRemoteSecret("AUTH_KEYS_SIGNING")
	}

	if signingKeys != "" {
		if entries := parsePEMKeys(signingKeys, "private_key"); len(entries) > 0 {
			v.SetDefault(prefix+".keys.signing", entries)
		}
	}

	// Load secondary key(s) from remote secret.
	secondaryKeys := os.Getenv("AUTH_KEYS_SECONDARY")
	if secondaryKeys == "" {
		secondaryKeys, _ = config.LoadRemoteSecret("AUTH_KEYS_SECONDARY")
	}

	if secondaryKeys != "" {
		if entries := parsePEMKeys(secondaryKeys, "public_key"); len(entries) > 0 {
			v.SetDefault(prefix+".keys.secondary", entries)
		}
	}

	_ = v.BindEnv(prefix+".keys.primary.private_key", "AUTH_KEYS_PRIMARY")
	_ = v.BindEnv(prefix+".keys.primary.algorithm", "AUTH_KEYS_PRIMARY_ALGORITHM")
}

// parsePEMKeys splits a blob of concatenated PEM blocks into one KeyConfig entry per block,
// assigning each block to the given field.
func parsePEMKeys(blob, field string) []map[string]string {
	var entries []map[string]string

	rest := []byte(blob)

	for {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		entries = append(entries, map[string]string{field: string(pem.EncodeToMemory(block))})
	}

	return entries
}

// Validate validates the authentication configuration section.
func (c *Configuration) Validate(valid *validation.Validate) error {
	return valid.Struct(c)
}
