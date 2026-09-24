package middleware

import (
	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// RequireACR halts the chain unless the authenticated user's session satisfies the named ACR
// level on a's configured ladder.
func RequireACR(a *auth.Auth, level string) azugo.RequestHandlerFunc {
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			if !a.ACRSatisfies(ctx.User().ClaimValue("acr"), level) {
				ctx.Error(auth.NewOAuthError(http.StatusForbidden, auth.ErrCodeUnmetAuthenticationRequirements, "authentication requirements not met"))

				return
			}

			next(ctx)
		}
	}
}
