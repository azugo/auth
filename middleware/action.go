package middleware

import (
	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// RequireSubject halts the chain unless the principal acts for the object of type named by the
// route parameter param.
func RequireSubject(typ, param string) azugo.RequestHandlerFunc {
	if typ == "" || param == "" {
		panic("middleware.RequireSubject: type and param are required")
	}

	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			if !auth.AuthorizationDetails(ctx.User()).ActsFor(typ, ctx.Params.String(param)) {
				ctx.Error(auth.NewOAuthError(http.StatusForbidden, auth.ErrCodeInsufficientScope, "subject not authorized"))

				return
			}

			next(ctx)
		}
	}
}

// RequireAction halts the chain unless the principal's authorization details allow action on the
// object of type named by the route parameter param.
func RequireAction(typ, param, action string) azugo.RequestHandlerFunc {
	if typ == "" || param == "" || action == "" {
		panic("middleware.RequireAction: type, param and action are required")
	}

	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			if !auth.AuthorizationDetails(ctx.User()).Allows(typ, ctx.Params.String(param), action) {
				ctx.Error(auth.NewOAuthError(http.StatusForbidden, auth.ErrCodeInsufficientScope, "action not authorized"))

				return
			}

			next(ctx)
		}
	}
}
