package middleware

import (
	"net/url"

	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// RequireAuthOption configures RequireAuth.
type RequireAuthOption func(*requireAuthOptions)

type requireAuthOptions struct {
	redirectTo string
	returnTo   bool
}

// RedirectTo makes RequireAuth redirect an anonymous request to path.
func RedirectTo(path string) RequireAuthOption {
	return func(o *requireAuthOptions) {
		o.redirectTo = path
	}
}

// ReturnTo appends the originally requested path and query string as a return_to query
// parameter on the RedirectTo target.
func ReturnTo() RequireAuthOption {
	return func(o *requireAuthOptions) {
		o.returnTo = true
	}
}

// RequireAuth halts the chain unless a prior Auth middleware resolved an authenticated user.
func RequireAuth(opts ...RequireAuthOption) azugo.RequestHandlerFunc {
	var o requireAuthOptions
	for _, opt := range opts {
		opt(&o)
	}

	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			if !ctx.User().Authorized() {
				if target := o.redirectTo; target != "" {
					if u, err := url.Parse(target); o.returnTo && err == nil {
						returnTo := ctx.Path()
						if raw := ctx.Query.Raw(); raw != "" {
							returnTo += "?" + raw
						}

						q := u.Query()
						q.Set("return_to", returnTo)
						u.RawQuery = q.Encode()
						target = u.String()
					}

					ctx.Redirect(target)

					return
				}

				ctx.Error(auth.NewOAuthError(http.StatusUnauthorized, auth.ErrCodeInvalidToken, "authentication required"))

				return
			}

			next(ctx)
		}
	}
}
