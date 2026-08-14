package auth

import (
	"context"
	"testing"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/core"
	"azugo.io/core/config"
	"github.com/go-quicktest/qt"
	"github.com/spf13/viper"
)

type stubUsers struct{}

func (stubUsers) Authenticate(_ context.Context, _, _ string) (UserInfo, error) {
	return UserInfo{}, nil
}

func (stubUsers) GetUser(_ context.Context, id string) (UserInfo, error) {
	return UserInfo{ID: id}, nil
}

func validConfig() *Configuration {
	return &Configuration{
		Secret:   "0123456789abcdef0123456789abcdef",
		SameSite: "strict",
		Issuer:   "https://issuer.example",
	}
}

func newApp(t *testing.T) *core.App {
	t.Helper()

	app := core.New()

	conf := config.New()
	qt.Assert(t, qt.IsNil(conf.Load(nil, conf, string(app.Env()))))
	app.SetConfig(nil, conf)

	t.Cleanup(app.Stop)

	return app
}

func TestNewMaterializesDefaultsAndAccessors(t *testing.T) {
	cfg := validConfig()

	a, err := New(newApp(t), cfg, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))

	// Defaults are materialised through the retained pointer, so a hand-built config validates.
	qt.Check(t, qt.Equals(cfg.AccessTokenTTL, 20*time.Minute))
	qt.Check(t, qt.Equals(cfg.SessionTTL, 8*time.Hour))
	qt.Check(t, qt.Equals(cfg.CookieName, "__session"))

	// Accessors expose the wired dependencies; Config returns the same retained pointer.
	qt.Check(t, qt.IsNotNil(a.Users()))
	qt.Check(t, qt.IsNotNil(a.Sessions()))
	qt.Check(t, qt.IsNotNil(a.Clients()))
	qt.Check(t, qt.IsNotNil(a.JTI())) // default cache-backed store
	qt.Check(t, qt.IsTrue(a.Config() == cfg))
}

func TestNewRequiresDependencies(t *testing.T) {
	app := newApp(t)

	_, err := New(app, validConfig(), nil, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Check(t, qt.IsNotNil(err))

	_, err = New(app, nil, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Check(t, qt.IsNotNil(err))

	_, err = New(nil, validConfig(), stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Check(t, qt.IsNotNil(err))
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cfg := validConfig()
	cfg.Secret = "tooshort"

	_, err := New(newApp(t), cfg, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Check(t, qt.IsNotNil(err))
}

type fakeJTI struct{}

func (fakeJTI) Issue(context.Context, string, string, time.Duration) error { return nil }
func (fakeJTI) Rotate(context.Context, string, string, string, time.Duration) (bool, error) {
	return true, nil
}
func (fakeJTI) Revoke(context.Context, string) error                   { return nil }
func (fakeJTI) Validate(context.Context, string, string) (bool, error) { return true, nil }

func TestJTIStoreOptionOverridesDefault(t *testing.T) {
	// A supplied JTI store skips the default cache-backed branch.
	a, err := New(newApp(t), validConfig(), stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry(),
		JTIStore(fakeJTI{}))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNotNil(a.JTI()))
}

func TestNewWithoutConfiguredKeysStaysIntrospectOnly(t *testing.T) {
	a, err := New(newApp(t), validConfig(), stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNil(a.Keys()))
}

func TestNewBuildsConfigKeyProviderFromConfigurationKeys(t *testing.T) {
	priv, pub := genTestRSAKeyPair(t)
	cfg := validConfig()
	cfg.Keys = &contract.KeySetConfig{
		Primary: contract.KeyConfig{ID: "k1", Algorithm: "RS256", PrivateKey: priv, PublicKey: pub},
	}

	a, err := New(newApp(t), cfg, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(a.Keys()))

	set, err := a.Keys().KeySet(context.Background())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(set.Primary.ID, "k1"))
}

func TestNewRejectsInvalidConfigurationKeys(t *testing.T) {
	cfg := validConfig()
	cfg.Keys = &contract.KeySetConfig{
		Primary: contract.KeyConfig{ID: "k1", Algorithm: "RS256", PrivateKey: "not pem", PublicKey: "not pem"},
	}

	_, err := New(newApp(t), cfg, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Check(t, qt.IsNotNil(err))
}

type fakeKeyProvider struct{}

func (fakeKeyProvider) KeySet(context.Context) (*token.KeySet, error) {
	return &token.KeySet{}, nil
}

func TestKeyProviderOptionOverridesConfigurationKeys(t *testing.T) {
	cfg := validConfig()
	// Invalid PEM: New must not attempt to parse this, proving KeyProvider() short-circuits
	// the Configuration.Keys default-provider branch entirely.
	cfg.Keys = &contract.KeySetConfig{
		Primary: contract.KeyConfig{ID: "k1", Algorithm: "RS256", PrivateKey: "not pem", PublicKey: "not pem"},
	}

	custom := fakeKeyProvider{}

	a, err := New(newApp(t), cfg, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry(),
		KeyProvider(custom))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(a.Keys(), token.KeyProvider(custom)))
}

// appConfig mirrors the wrapper every consumer (e.g. the portal example) uses to embed the
// auth section into their own configuration, so Bind is exercised through the real
// core/config.Configuration.Load pipeline rather than a hand-built *Configuration.
type appConfig struct {
	*config.Configuration `mapstructure:",squash"`

	Auth *Configuration `mapstructure:"auth"`
}

func (c *appConfig) Bind(_ string, v *viper.Viper) {
	c.Auth = config.Bind(c.Auth, "auth", v)
}

// newAppWithEnvConfig loads configuration the way a real application does: AUTH_* environment
// variables flow through Configuration.Bind and viper.Unmarshal, not a hand-built struct.
func newAppWithEnvConfig(t *testing.T) (*core.App, *Configuration) {
	t.Helper()

	app := core.New()

	cfg := &appConfig{Configuration: config.New()}
	qt.Assert(t, qt.IsNil(cfg.Load(nil, cfg, string(app.Env()))))
	app.SetConfig(nil, cfg.Configuration)

	cfg.Auth.Secret = "0123456789abcdef0123456789abcdef"
	cfg.Auth.SameSite = "strict"
	cfg.Auth.Issuer = "https://issuer.example"

	t.Cleanup(app.Stop)

	return app, cfg.Auth
}

// TestNewBuildsConfigKeyProviderFromEnvBoundKeys covers the full chain the isolated Bind/New
// tests don't: AUTH_KEYS_PRIMARY set as an environment variable reaches a working KeyProvider
// through the real config-loading pipeline, not a hand-built contract.KeySetConfig.
func TestNewBuildsConfigKeyProviderFromEnvBoundKeys(t *testing.T) {
	priv, _ := genTestRSAKeyPair(t)

	t.Setenv("AUTH_KEYS_PRIMARY", priv)
	t.Setenv("AUTH_KEYS_PRIMARY_ALGORITHM", "RS256")

	app, cfg := newAppWithEnvConfig(t)
	qt.Assert(t, qt.IsNotNil(cfg.Keys))

	a, err := New(app, cfg, stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(a.Keys()))

	set, err := a.Keys().KeySet(context.Background())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(set.Primary.Algorithm, "RS256"))
	qt.Check(t, qt.IsNotNil(set.Primary.Public))
}
