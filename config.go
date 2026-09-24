package auth

import (
	"azugo.io/auth/contract"
)

// Configuration is the authentication configuration section.
type Configuration = contract.Configuration

// ExternalProviderConfig configures one external IdP driver instance.
type ExternalProviderConfig = contract.ExternalProviderConfig

// MFAMethodConfig configures one MFA method driver instance.
type MFAMethodConfig = contract.MFAMethodConfig

// ACRLevelConfig defines one authentication context class.
type ACRLevelConfig = contract.ACRLevelConfig

// LogoutPolicy is what GET /logout must carry before it ends a session.
type LogoutPolicy = contract.LogoutPolicy

// LogoutPolicy values.
const (
	LogoutPolicyCookie      = contract.LogoutPolicyCookie
	LogoutPolicyConfirm     = contract.LogoutPolicyConfirm
	LogoutPolicyIDTokenHint = contract.LogoutPolicyIDTokenHint
)
