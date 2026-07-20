package auth

import (
	"strings"
	"time"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// WriteCookie applies a CookieDirective to the response.
func (a *Auth) WriteCookie(ctx *azugo.Context, d *CookieDirective) {
	if d == nil {
		return
	}

	sameSite := azugo.CookieSameSiteStrict

	switch d.SameSite {
	case "lax":
		sameSite = azugo.CookieSameSiteLax
	case "none":
		sameSite = azugo.CookieSameSiteNone
	}

	opts := make([]azugo.CookieOption, 0, 6)
	opts = append(opts,
		azugo.CookiePath(d.Path),
		azugo.CookieDomain(d.Domain),
		azugo.CookieHTTPOnly(d.HTTPOnly),
		azugo.CookieSecure(d.Secure),
		sameSite,
	)

	if d.MaxAge < 0 {
		ctx.Cookie.Clear(d.Name, opts...)

		return
	}

	opts = append(opts, azugo.CookieMaxAge(time.Duration(d.MaxAge)*time.Second))
	ctx.Cookie.Set(d.Name, d.Value, opts...)
}

// ReadSessionToken extracts the presented credential.
func (a *Auth) ReadSessionToken(ctx *azugo.Context) string {
	if tok, ok := strings.CutPrefix(ctx.Header.Get(http.HeaderAuthorization), "Bearer "); ok && tok != "" {
		return tok
	}

	return ctx.Cookie.Get(a.config.CookieName)
}
