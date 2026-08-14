// Package middleware provides azugo HTTP middleware over the transport-free auth service.
package middleware

import (
	"strings"

	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// AuthOption configures Auth.
type AuthOption interface {
	apply(o *authOptions)
}

type authOptions struct {
	useCookie bool
}

// Cookie enables the session cookie as a credential source.
func Cookie() AuthOption {
	return cookieOption{}
}

type cookieOption struct{}

func (cookieOption) apply(o *authOptions) {
	o.useCookie = true
}

// Auth resolves the current user from the Authorization if present.
func Auth(a *auth.Auth, opts ...AuthOption) azugo.RequestHandlerFunc {
	var o authOptions
	for _, opt := range opts {
		opt.apply(&o)
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

			// Opaque PASETO tokens validate through the session-store introspection, JWT
			// bearer tokens by signature + revocation deny-list.
			if strings.HasPrefix(tok, "v4.local.") {
				if info, _, err := a.IntrospectToken(ctx, tok); err == nil {
					ctx.SetUser(info.ToUser())
				}
			} else if tok != "" {
				if info, err := a.ValidateJWTAccessToken(ctx, tok); err == nil {
					ctx.SetUser(info.ToUser())
				}
			}

			next(ctx)
		}
	}
}
