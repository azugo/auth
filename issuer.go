package auth

import "strings"

// IssuerCtx provides OIDC issuer resolution helpers derived from the auth configuration.
type IssuerCtx struct {
	noCopy noCopy

	config *Configuration
}

// URL returns the effective OIDC issuer.
func (c *IssuerCtx) URL(baseURL, mountPath string) string {
	if c.config.Issuer != "" {
		return c.config.Issuer
	}

	if c.config.BaseURL != "" {
		baseURL = c.config.BaseURL
	}

	base := strings.TrimRight(baseURL, "/")

	if mount := strings.Trim(mountPath, "/"); mount != "" {
		return base + "/" + mount
	}

	return base
}
