package routes

import (
	"example/portal/views"

	"azugo.io/azugo"
	"azugo.io/templ"
)

func (r *router) home(ctx *azugo.Context) {
	name := ""
	if ctx.User().Authorized() {
		name = ctx.User().DisplayName()
	}

	templ.Render(ctx, views.Home(name))
}
