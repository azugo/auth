package routes

import (
	"azugo.io/auth"

	"azugo.io/azugo"
)

func (r *router) logout(ctx *azugo.Context) {
	res, err := r.Auth().Logout(ctx, auth.LogoutRequest{
		Token:    r.Auth().ReadSessionToken(ctx),
		BasePath: ctx.BasePath(),
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	r.Auth().WriteCookie(ctx, res.ClearCookie)
	ctx.Redirect("/")
}
