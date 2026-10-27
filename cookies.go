package auth

import (
	"time"

	"azugo.io/auth/dpop"

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

// ReadSessionToken extracts the presented credential: the access token of a Bearer or DPoP
// Authorization header, else the session cookie. The header token's DPoP binding is checked by
// middleware.DPoP or middleware.Auth in front of the handler.
func (a *Auth) ReadSessionToken(ctx *azugo.Context) string {
	if tok, _ := dpop.Credential(ctx.Header.Get(http.HeaderAuthorization)); tok != "" {
		return tok
	}

	return a.ReadSessionCookie(ctx)
}

// ReadSessionCookie returns the session cookie's token, "" when the cookie is missing or holds
// anything but a session cookie.
func (a *Auth) ReadSessionCookie(ctx *azugo.Context) string {
	tok := ctx.Cookie.Get(a.config.CookieName)
	if tok == "" {
		return ""
	}

	if _, err := a.codec.DecodeSessionCookie(tok); err != nil {
		return ""
	}

	return tok
}
