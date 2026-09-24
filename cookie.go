package auth

import (
	"net/url"
	"strings"

	"azugo.io/azugo"
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

// SameSite returns the effective cookie SameSite mode based on configuration.
func (c *CookieCtx) SameSite() azugo.CookieSameSite {
	switch c.config.SameSite {
	case "strict":
		return azugo.CookieSameSiteStrict
	case "lax":
		return azugo.CookieSameSiteLax
	case "none":
		return azugo.CookieSameSiteNone
	}

	if c.app.Env().IsDevelopment() {
		return azugo.CookieSameSiteLax
	}

	return azugo.CookieSameSiteStrict
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
