package auth

import (
	"azugo.io/auth/contract"
)

// Configuration is the authentication configuration section.
type Configuration = contract.Configuration

// ExternalProviderConfig configures one external IdP driver instance.
type ExternalProviderConfig = contract.ExternalProviderConfig
