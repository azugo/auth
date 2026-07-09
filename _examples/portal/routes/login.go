package routes

import (
	"errors"

	"example/portal/views"

	"azugo.io/auth"
	"azugo.io/azugo"
	"azugo.io/templ"
)

func (r *router) loginForm(ctx *azugo.Context) {
	templ.Render(ctx, views.Login(""))
}

// login validates credentials directly against the UserProvider. It is a stand-in until
// Phase 2 mounts POST /auth/token with the cookie response mode.
func (r *router) login(ctx *azugo.Context) {
	username, err := ctx.Form.String("username")
	if err != nil {
		ctx.Error(err)

		return
	}

	password, err := ctx.Form.String("password")
	if err != nil {
		ctx.Error(err)

		return
	}

	user, err := r.Auth().Users().Authenticate(ctx, username, password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			templ.Render(ctx, views.Login("Invalid username or password."))

			return
		}

		ctx.Error(err)

		return
	}

	templ.Render(ctx, views.Home(user.Name))
}
