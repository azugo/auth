package routes

import (
	"azugo.io/auth"

	"azugo.io/azugo"
)

// authorize implements POST /authorize: the portal's silent re-authentication over the
// existing session cookie.
func (h *Handler) authorize(ctx *azugo.Context) {
	returnTo := ""
	if v := ctx.Query.StringOptional("return_to"); v != nil {
		returnTo = *v
	}

	res, err := h.auth.Refresh(ctx, auth.RefreshRequest{
		Token:      ctx.Cookie.Get(h.auth.Config().CookieName),
		ReturnTo:   returnTo,
		RequestTLS: ctx.IsTLS(),
		BasePath:   ctx.BasePath(),
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	h.writeLoginResult(ctx, res)
}
