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

	opts := make([]azugo.CookieOption, 0, 4)
	opts = append(opts,
		azugo.CookieDefaultSecurity(),
		azugo.CookiePath(d.Path),
		d.SameSite,
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
