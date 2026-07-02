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
	qt.Check(t, qt.IsTrue(v.GetBool("auth.secure")))
	qt.Check(t, qt.IsTrue(v.GetBool("auth.logout_invalidates_cookie")))
	qt.Check(t, qt.Equals(v.GetString("auth.same_site"), "strict"))
	qt.Check(t, qt.Equals(v.GetDuration("auth.access_token_ttl"), 20*time.Minute))
	qt.Check(t, qt.Equals(v.GetDuration("auth.session_ttl"), 8*time.Hour))
	qt.Check(t, qt.Equals(v.GetDuration("auth.code_ttl"), 60*time.Second))
	qt.Check(t, qt.IsTrue(v.GetBool("auth.throttle.enabled")))
	qt.Check(t, qt.Equals(v.GetInt("auth.throttle.max_attempts"), 5))
	qt.Check(t, qt.Equals(v.GetDuration("auth.throttle.mfa_resend_cooldown"), 60*time.Second))
	qt.Check(t, qt.Equals(v.GetInt("auth.throttle.mfa_max_resends"), 3))
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

	badIssuer := *valid
	badIssuer.Issuer = "not-a-url"
	qt.Check(t, qt.IsNotNil(badIssuer.Validate(validation.New())))
}
