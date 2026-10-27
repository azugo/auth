package middleware

import (
	"azugo.io/auth"

	"azugo.io/azugo"
)

// DPoP answers a credential failing its DPoP binding with the RFC 9449 challenge; the handlers
// behind it read the verified token through ReadSessionToken. A Handler mounted outside routes.Bind
// needs it in front.
func DPoP(a *auth.Auth) azugo.RequestHandlerFunc {
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			if _, err := a.ReadAccessToken(ctx); err != nil {
				ctx.Error(err)

				return
			}

			next(ctx)
		}
	}
}
