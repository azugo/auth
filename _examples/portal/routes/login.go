package routes

import (
	"net/url"

	"example/portal/views"

	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/templ"
)

// portalClientID is the registered client the portal signs users in as.
const portalClientID = "portal"

// loginForm renders the sign-in page. A return_to query parameter is carried through as a hidden
// field so Login lands the user back where they started.
func (r *router) loginForm(ctx *azugo.Context) {
	returnTo := ""
	if v := ctx.Query.StringOptional("return_to"); v != nil {
		returnTo = *v
	}

	var username string

	_, _ = ctx.Flash.Get("username", &username)

	templ.Render(ctx, views.Login(username, ctx.Flash.FieldErrorFor("password"), returnTo))
}

// login handles the sign-in form by calling the transport-free service tier directly.
func (r *router) login(ctx *azugo.Context) {
	req := auth.LoginRequest{
		Credentials: auth.ClientCredentials{ClientID: portalClientID},
		BaseURL:     ctx.BaseURL(),
		IP:          ctx.IP().String(),
	}

	if v := ctx.Form.StringOptional("username"); v != nil {
		req.Username = *v
	}

	if v := ctx.Form.StringOptional("password"); v != nil {
		req.Password = *v
	}

	if v := ctx.Form.StringOptional("return_to"); v != nil {
		req.ReturnTo = *v
	}

	res, err := r.Auth().Login(ctx, req)
	if err != nil {
		if r.fatal(ctx, err, req.ReturnTo) {
			return
		}

		ctx.Flash.FieldError("password", errorMessage(err, "Invalid username or password."))
		_ = ctx.Flash.Set("username", req.Username)
		ctx.Redirect(pageURL("/login", req.ReturnTo))

		return
	}

	r.Auth().WriteCookie(ctx, res.Cookie)
	ctx.Redirect(res.ReturnTo)
}

// pageURL appends return_to to a local page path when set.
func pageURL(path, returnTo string) string {
	if returnTo == "" {
		return path
	}

	return path + "?return_to=" + url.QueryEscape(returnTo)
}
