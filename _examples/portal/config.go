package portal

import (
	"azugo.io/auth"

	"azugo.io/azugo/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration is the example portal configuration.
type Configuration struct {
	*config.Configuration `mapstructure:",squash"`

	Auth *auth.Configuration `mapstructure:"auth"`
	// PushCallbackSecret authenticates the push MFA webhook; unset leaves push without approvals.
	PushCallbackSecret string `mapstructure:"push_callback_secret"`
}

// NewConfiguration creates the portal configuration.
func NewConfiguration() *Configuration {
	return &Configuration{
		Configuration: config.New(),
	}
}

// Bind registers defaults and environment variable bindings with viper.
func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.Configuration.Bind("", v)

	c.Auth = config.Bind(c.Auth, "auth", v)

	_ = v.BindEnv("push_callback_secret", "PUSH_CALLBACK_SECRET")
}

// Validate validates the full configuration.
func (c *Configuration) Validate(validate *validation.Validate) error {
	if err := c.Auth.Validate(validate); err != nil {
		return err
	}

	return validate.Struct(c)
}
