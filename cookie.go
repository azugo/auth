package auth

import (
	"net/url"
	"strings"

	"azugo.io/core"
)

// CookieCtx provides session cookie attribute helpers derived from the auth
// configuration and app environment.
type CookieCtx struct {
	noCopy noCopy

	config          *Configuration
	app             *core.App
	scopeToBasePath bool
}

// Secure returns the effective cookie Secure flag for a request based on configuration.
func (c *CookieCtx) Secure(requestTLS bool) bool {
	if c.config.Secure != nil {
		return *c.config.Secure
	}

	return requestTLS || !c.app.Env().IsDevelopment()
}

// SameSite returns the effective cookie SameSite mode based on configuration.
func (c *CookieCtx) SameSite() string {
	if c.config.SameSite != "" {
		return c.config.SameSite
	}

	if c.app.Env().IsDevelopment() {
		return "lax"
	}

	return "strict"
}

// Path returns the effective session cookie path based on configuration.
func (c *CookieCtx) Path(baseURL, mountPath string) string {
	if c.config.CookiePath != "" {
		return c.config.CookiePath
	}

	if c.scopeToBasePath {
		mountPath = ""
	}

	if c.config.BaseURL != "" {
		baseURL = c.config.BaseURL
	}

	basePath := ""
	if u, err := url.Parse(baseURL); err == nil {
		basePath = u.Path
	}

	base := "/" + strings.Trim(basePath, "/")

	if mount := strings.Trim(mountPath, "/"); mount != "" {
		if base == "/" {
			return "/" + mount
		}

		return base + "/" + mount
	}

	return base
}
