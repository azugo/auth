package contract

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"azugo.io/core/validation"
	"github.com/go-quicktest/qt"
	"github.com/spf13/viper"
)

func TestBindDefaults(t *testing.T) {
	v := viper.New()
	(&Configuration{}).Bind("auth", v)

	qt.Check(t, qt.Equals(v.GetString("auth.cookie_name"), "__session"))
	qt.Check(t, qt.IsNil(v.Get("auth.secure")))    // no default: unset = runtime resolution
	qt.Check(t, qt.IsNil(v.Get("auth.same_site"))) // no default: unset = runtime resolution
	qt.Check(t, qt.IsTrue(v.GetBool("auth.logout_invalidates_cookie")))
	qt.Check(t, qt.Equals(v.GetDuration("auth.access_token_ttl"), 20*time.Minute))
	qt.Check(t, qt.Equals(v.GetDuration("auth.session_ttl"), 8*time.Hour))
	qt.Check(t, qt.Equals(v.GetDuration("auth.code_ttl"), 60*time.Second))
	qt.Check(t, qt.IsTrue(v.GetBool("auth.throttle.enabled")))
	qt.Check(t, qt.Equals(v.GetInt("auth.throttle.max_attempts"), 5))
	qt.Check(t, qt.Equals(v.GetDuration("auth.throttle.mfa_resend_cooldown"), 60*time.Second))
	qt.Check(t, qt.Equals(v.GetInt("auth.throttle.mfa_max_resends"), 3))
}

// TestSecureUnmarshal guards the tri-state Secure decode through the root viper Unmarshal
// used by the config loader: an env-bound value must reach the pointer field and an unset
// key must leave it nil. UnmarshalKey would miss env-only keys - the loader uses Unmarshal.
func TestSecureUnmarshal(t *testing.T) {
	type root struct {
		Auth *Configuration `mapstructure:"auth"`
	}

	v := viper.New()
	c := &Configuration{}
	c.Bind("auth", v)

	r := &root{Auth: c}
	qt.Assert(t, qt.IsNil(v.Unmarshal(r)))
	qt.Check(t, qt.IsNil(r.Auth.Secure))

	t.Setenv("AUTH_SECURE", "false")

	v2 := viper.New()
	c2 := &Configuration{}
	c2.Bind("auth", v2)

	r2 := &root{Auth: c2}
	qt.Assert(t, qt.IsNil(v2.Unmarshal(r2)))
	qt.Assert(t, qt.IsNotNil(r2.Auth.Secure))
	qt.Check(t, qt.IsFalse(*r2.Auth.Secure))
}

// TestBindSameSiteEnv guards the previously-broken AUTH_SAME_SITE binding (it was bound to
// the "secure" key, so the env var was silently ignored).
func TestBindSameSiteEnv(t *testing.T) {
	t.Setenv("AUTH_SAME_SITE", "lax")

	v := viper.New()
	(&Configuration{}).Bind("auth", v)

	qt.Check(t, qt.Equals(v.GetString("auth.same_site"), "lax"))
}

func TestValidate(t *testing.T) {
	valid := &Configuration{
		Secret:         "0123456789abcdef0123456789abcdef",
		SameSite:       "strict",
		AccessTokenTTL: 20 * time.Minute,
		SessionTTL:     8 * time.Hour,
		Issuer:         "https://issuer.example",
	}
	qt.Check(t, qt.IsNil(valid.Validate(validation.New())))

	short := *valid
	short.Secret = "tooshort"
	qt.Check(t, qt.IsNotNil(short.Validate(validation.New())))

	badSameSite := *valid
	badSameSite.SameSite = "bogus"
	qt.Check(t, qt.IsNotNil(badSameSite.Validate(validation.New())))

	unsetSameSite := *valid
	unsetSameSite.SameSite = "" // unset = runtime resolution
	qt.Check(t, qt.IsNil(unsetSameSite.Validate(validation.New())))

	badIssuer := *valid
	badIssuer.Issuer = "not-a-url"
	qt.Check(t, qt.IsNotNil(badIssuer.Validate(validation.New())))
}

// genTestRSAKeyPair generates a fresh RSA key pair PEM-encoded as PKCS#8 (private) / PKIX
// (public), for AUTH_KEYS_* env binding tests.
func genTestRSAKeyPair(t *testing.T) (priv, pub string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	qt.Assert(t, qt.IsNil(err))

	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	qt.Assert(t, qt.IsNil(err))

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	qt.Assert(t, qt.IsNil(err))

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
}

type keysRoot struct {
	Auth *Configuration `mapstructure:"auth"`
}

func bindAndUnmarshalKeys(t *testing.T) *KeySetConfig {
	t.Helper()

	v := viper.New()
	c := &Configuration{}
	c.Bind("auth", v)

	r := &keysRoot{Auth: c}
	qt.Assert(t, qt.IsNil(v.Unmarshal(r)))

	return r.Auth.Keys
}

// TestBindKeysStaysNilWithoutEnvVars guards the critical nil-safety requirement: Keys is an
// optional *KeySetConfig, and an unconditional default under "keys.*" would make it non-nil
// for every app regardless of whether Keys is configured, silently breaking introspect-only
// mode.
func TestBindKeysStaysNilWithoutEnvVars(t *testing.T) {
	qt.Check(t, qt.IsNil(bindAndUnmarshalKeys(t)))
}

func TestBindKeysPrimaryFromEnvVar(t *testing.T) {
	priv, _ := genTestRSAKeyPair(t)

	t.Setenv("AUTH_KEYS_PRIMARY", priv)
	t.Setenv("AUTH_KEYS_PRIMARY_ALGORITHM", "RS256")

	keys := bindAndUnmarshalKeys(t)
	qt.Assert(t, qt.IsNotNil(keys))
	qt.Check(t, qt.Equals(keys.Primary.PrivateKey, priv))
	qt.Check(t, qt.Equals(keys.Primary.Algorithm, "RS256"))
}

func TestBindKeysPrimaryFromFile(t *testing.T) {
	priv, _ := genTestRSAKeyPair(t)

	path := filepath.Join(t.TempDir(), "primary.pem")
	qt.Assert(t, qt.IsNil(os.WriteFile(path, []byte(priv), 0o600)))

	t.Setenv("AUTH_KEYS_PRIMARY_FILE", path)

	keys := bindAndUnmarshalKeys(t)
	qt.Assert(t, qt.IsNotNil(keys))
	qt.Check(t, qt.Equals(keys.Primary.PrivateKey, strings.TrimSpace(priv)))
}

func TestBindKeysPrimaryEnvVarOverridesFile(t *testing.T) {
	filePriv, _ := genTestRSAKeyPair(t)
	envPriv, _ := genTestRSAKeyPair(t)

	path := filepath.Join(t.TempDir(), "primary.pem")
	qt.Assert(t, qt.IsNil(os.WriteFile(path, []byte(filePriv), 0o600)))

	t.Setenv("AUTH_KEYS_PRIMARY_FILE", path)
	t.Setenv("AUTH_KEYS_PRIMARY", envPriv)

	keys := bindAndUnmarshalKeys(t)
	qt.Assert(t, qt.IsNotNil(keys))
	qt.Check(t, qt.Equals(keys.Primary.PrivateKey, envPriv))
}

func TestBindKeysSigningFromEnvVar(t *testing.T) {
	priv1, _ := genTestRSAKeyPair(t)
	priv2, _ := genTestRSAKeyPair(t)

	t.Setenv("AUTH_KEYS_SIGNING", priv1+priv2)

	keys := bindAndUnmarshalKeys(t)
	qt.Assert(t, qt.IsNotNil(keys))
	qt.Assert(t, qt.HasLen(keys.Signing, 2))
	qt.Check(t, qt.Equals(strings.TrimSpace(keys.Signing[0].PrivateKey), strings.TrimSpace(priv1)))
	qt.Check(t, qt.Equals(strings.TrimSpace(keys.Signing[1].PrivateKey), strings.TrimSpace(priv2)))
}

func TestBindKeysSigningFromFile(t *testing.T) {
	priv, _ := genTestRSAKeyPair(t)

	path := filepath.Join(t.TempDir(), "signing.pem")
	qt.Assert(t, qt.IsNil(os.WriteFile(path, []byte(priv), 0o600)))

	t.Setenv("AUTH_KEYS_SIGNING_FILE", path)

	keys := bindAndUnmarshalKeys(t)
	qt.Assert(t, qt.IsNotNil(keys))
	qt.Assert(t, qt.HasLen(keys.Signing, 1))
	qt.Check(t, qt.Equals(strings.TrimSpace(keys.Signing[0].PrivateKey), strings.TrimSpace(priv)))
}

func TestBindKeysSecondaryFromEnvVar(t *testing.T) {
	_, pub1 := genTestRSAKeyPair(t)
	_, pub2 := genTestRSAKeyPair(t)

	t.Setenv("AUTH_KEYS_SECONDARY", pub1+pub2)

	keys := bindAndUnmarshalKeys(t)
	qt.Assert(t, qt.IsNotNil(keys))
	qt.Assert(t, qt.HasLen(keys.Secondary, 2))
	qt.Check(t, qt.Equals(strings.TrimSpace(keys.Secondary[0].PublicKey), strings.TrimSpace(pub1)))
	qt.Check(t, qt.Equals(strings.TrimSpace(keys.Secondary[1].PublicKey), strings.TrimSpace(pub2)))
}

func TestBindKeysSecondaryFromFile(t *testing.T) {
	_, pub1 := genTestRSAKeyPair(t)
	_, pub2 := genTestRSAKeyPair(t)

	path := filepath.Join(t.TempDir(), "secondary.pem")
	qt.Assert(t, qt.IsNil(os.WriteFile(path, []byte(pub1+pub2), 0o600)))

	t.Setenv("AUTH_KEYS_SECONDARY_FILE", path)

	keys := bindAndUnmarshalKeys(t)
	qt.Assert(t, qt.IsNotNil(keys))
	qt.Assert(t, qt.HasLen(keys.Secondary, 2))
}
