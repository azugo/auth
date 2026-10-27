package middleware

import (
	"azugo.io/azugo"
	"azugo.io/core/http"
)

// SecurityHeaders marks responses as non-cacheable (RFC 6749 §5.1) and disables content-type
// sniffing.
func SecurityHeaders(next azugo.RequestHandler) azugo.RequestHandler {
	return func(ctx *azugo.Context) {
		ctx.Header.Set(http.HeaderCacheControl, "no-store")
		ctx.Header.Set(http.HeaderPragma, "no-cache")
		ctx.Header.Set(http.HeaderXContentTypeOptions, "nosniff")

		next(ctx)
	}
}
