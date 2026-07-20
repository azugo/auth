package routes

import (
	"example/portal/views"

	"azugo.io/azugo"
	"azugo.io/templ"
)

// loginForm renders the sign-in page. The form posts directly to the library's own
// POST /auth/token (password grant, see auth/routes.OIDCRoutes.Token) - the portal no longer
// validates credentials itself. A return_to query parameter (set by RequireAuth's ReturnTo
// option when redirecting an anonymous request here) is carried through as a hidden field so
// Login lands the user back where they started.
func (r *router) loginForm(ctx *azugo.Context) {
	returnTo := ""
	if v := ctx.Query.StringOptional("return_to"); v != nil {
		returnTo = *v
	}

	templ.Render(ctx, views.Login("", returnTo))
}
