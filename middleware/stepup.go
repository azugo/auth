package middleware

import (
	"azugo.io/auth"

	"azugo.io/azugo"
)

// RequireStepUp halts the chain unless the session behind the request meets the step-up policy
// for action, answering 401 insufficient_user_authentication otherwise.
func RequireStepUp(a *auth.Auth, action string) azugo.RequestHandlerFunc {
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			if _, err := a.RequireStepUp(ctx, a.ReadSessionToken(ctx), action); err != nil {
				ctx.Error(err)

				return
			}

			next(ctx)
		}
	}
}
