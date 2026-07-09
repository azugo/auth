package contract

import (
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
