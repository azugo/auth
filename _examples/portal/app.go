// Package portal is an example server-side rendered portal built on azugo.io/auth.
package portal

import (
	"azugo.io/auth"
	"azugo.io/auth/client"
	"azugo.io/auth/mfa"
	_ "azugo.io/auth/mfa/recovery" // registers the "recovery" (backup codes) MFA driver
	_ "azugo.io/auth/mfa/totp"     // registers the "totp" MFA driver
	"azugo.io/auth/session"

	"example/portal/push"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	"github.com/spf13/cobra"
)

// App is the example portal application container.
type App struct {
	*azugo.App

	config *Configuration
	auth   *auth.Auth
}

// New creates the example portal application.
func New(cmd *cobra.Command, version string) (*App, error) {
	config := NewConfiguration()

	a, err := server.New(cmd, server.Options{
		AppName:       "Auth Portal Example",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	clients := client.NewMemoryRegistry(&client.Client{
		ID:                      "portal",
		Name:                    "Example Portal",
		Public:                  true,
		AllowNoPrompt:           true,
		GrantTypes:              []string{client.GrantTypePassword},
		Scopes:                  []string{"openid", "profile"},
		AllowedAuthMethods:      []string{client.AuthMethodPassword},
		ResponseMode:            client.ResponseModeRedirect,
		TokenEndpointAuthMethod: client.TokenEndpointAuthNone,
		// MFA is prompted once a user has enrolled an authenticator app on /security; a pending
		// login is redirected to the /mfa page.
		MFAPolicy:       client.MFAPolicyOptional,
		StepRedirectURI: "/mfa",
	})

	if config.PushCallbackSecret != "" {
		config.Auth.MFAMethods = append(config.Auth.MFAMethods, auth.MFAMethodConfig{
			Driver: push.DriverName,
			Config: map[string]string{"callback_secret": config.PushCallbackSecret},
		})
	}

	au, err := auth.New(a.App, config.Auth, NewDemoUsers(), session.NewMemoryStore(), clients,
		auth.CookieScopeToBasePath(), auth.MFAStore(mfa.NewMemoryStore()))
	if err != nil {
		return nil, err
	}

	return &App{
		App:    a,
		config: config,
		auth:   au,
	}, nil
}

// Config returns application configuration. Panics if not loaded.
func (a *App) Config() *Configuration {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}

	return a.config
}

// Auth returns the authentication service.
func (a *App) Auth() *auth.Auth {
	return a.auth
}
