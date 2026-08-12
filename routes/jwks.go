package routes

import (
	"azugo.io/auth/token"

	"azugo.io/azugo"
)

// jwks implements GET /.well-known/jwks.json.
func (h *Handler) jwks(ctx *azugo.Context) {
	set, err := h.auth.Keys().KeySet(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	jwks := token.JWKSFrom(set)
	ctx.JSON(&jwks)
}
