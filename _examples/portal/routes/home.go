package routes

import (
	"example/portal/views"

	"azugo.io/azugo"
	"azugo.io/templ"
)

func (r *router) home(ctx *azugo.Context) {
	templ.Render(ctx, views.Home(""))
}
