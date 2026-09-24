// Package middleware provides azugo HTTP middleware over the transport-free auth service.
package middleware

import (
	"slices"
	"strings"

	"azugo.io/auth"
	"azugo.io/auth/token"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// AuthOption configures Auth.
type AuthOption interface {
	apply(o *authOptions)
}

type authOptions struct {
	useCookie bool
	audiences []string
}

// Cookie enables the session cookie as a credential source.
func Cookie() AuthOption {
	return cookieOption{}
}

type cookieOption struct{}

func (cookieOption) apply(o *authOptions) {
	o.useCookie = true
}

// Audience restricts Auth to credentials issued to one of the given client IDs.
func Audience(clientIDs ...string) AuthOption {
	return audience(clientIDs)
}

type audience []string

func (o audience) apply(opts *authOptions) {
	opts.audiences = o
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
			var (
				info auth.UserInfo
				err  error
			)

			switch {
			case strings.HasPrefix(tok, "v4.local."):
				info, _, err = a.IntrospectToken(ctx, tok)
			case tok != "":
				info, err = a.ValidateJWTAccessToken(ctx, tok)
			default:
				err = token.ErrInvalidToken
			}

			if err == nil && (len(o.audiences) == 0 || slices.Contains(o.audiences, info.ClientID)) {
				ctx.SetUser(info.ToUser())
			}

			next(ctx)
		}
	}
}
