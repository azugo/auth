// Package middleware provides azugo HTTP middleware over the transport-free auth service.
package middleware

import (
	"strings"

	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// AuthOption configures Auth.
type AuthOption func(*authOptions)

type authOptions struct {
	useCookie bool
}

// Cookie enables the session cookie as a credential source.
func Cookie() AuthOption {
	return func(o *authOptions) {
		o.useCookie = true
	}
}

// Auth resolves the current user from the Authorization if present.
func Auth(a *auth.Auth, opts ...AuthOption) azugo.RequestHandlerFunc {
	var o authOptions
	for _, opt := range opts {
		opt(&o)
	}

	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			tok, ok := strings.CutPrefix(ctx.Header.Get(http.HeaderAuthorization), "Bearer ")
			if !ok {
				tok = ""
			}

			if tok == "" && o.useCookie {
				tok = ctx.Cookie.Get(a.Config().CookieName)
			}

			if tok != "" {
				if info, _, err := a.IntrospectToken(ctx, tok); err == nil {
					ctx.SetUser(info.ToUser())
				}
			}

			next(ctx)
		}
	}
}
