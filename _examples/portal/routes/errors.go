package routes

import (
	"errors"
	"strconv"
	"strings"

	"example/portal/views"

	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"azugo.io/templ"
	"go.uber.org/zap"
)

// messages for library errors
var wording = map[auth.ErrorCode]string{
	auth.ErrCodeInvalidToken:                    "Your sign-in has expired. Please start over.",
	auth.ErrCodeLoginRequired:                   "Your sign-in has expired. Please start over.",
	auth.ErrCodeUnmetAuthenticationRequirements: "This sign-in does not meet the required security level.",
}

// fatal takes over a failed request the form cannot recover from.
func (r *router) fatal(ctx *azugo.Context, err error, returnTo string) bool {
	var oe *auth.OAuthError

	switch {
	case !errors.As(err, &oe) || oe.StatusCode() >= http.StatusInternalServerError:
		ctx.Error(err)
	case oe.Code == auth.ErrCodeInvalidToken:
		ctx.Flash.FieldError("password", wording[oe.Code])
		ctx.Redirect(pageURL("/login", returnTo))
	default:
		return false
	}

	return true
}

// errorMessage turns a rejected request into text safe to show under a form field.
func errorMessage(err error, invalid string) string {
	var oe *auth.OAuthError
	if !errors.As(err, &oe) {
		return "Something went wrong. Please try again."
	}

	switch {
	case oe.Code == auth.ErrCodeInvalidGrant:
		return invalid
	case oe.Code == auth.ErrCodeSlowDown:
		return "Too many attempts. Try again in " + strconv.Itoa(int(oe.RetryAfter.Seconds()+0.999)) + " seconds."
	}

	if msg, ok := wording[oe.Code]; ok {
		return msg
	}

	return oe.Description
}

// errorPage is the router's ErrorHandler: it renders the generic error page for portal pages.
func (r *router) errorPage(ctx *azugo.Context, err error) bool {
	if err == nil || strings.HasPrefix(ctx.Path(), "/auth/") || ctx.AcceptsExplicit(http.ContentTypeJSON) {
		return false
	}

	status := http.StatusInternalServerError

	var sc http.ResponseStatusCode
	if errors.As(err, &sc) {
		status = sc.StatusCode()
	}

	message := "Something went wrong. Please try again later."

	var safe azugo.SafeError
	if status < http.StatusInternalServerError && errors.As(err, &safe) && safe.SafeError() != "" {
		message = safe.SafeError()
	} else if status >= http.StatusInternalServerError {
		ctx.Log().Error(err.Error(), zap.Error(err))
	}

	if ctx.Method() == http.MethodPost {
		ctx.Flash.Error(message)
		_ = ctx.Flash.Set("status", status)
		ctx.Redirect("/error")

		return true
	}

	ctx.StatusCode(status)
	templ.Render(ctx, views.Error(http.StatusMessage(status), message, r.backURL(ctx)))

	return true
}

// errorRedirected renders the error page for a form submit errorPage redirected here.
func (r *router) errorRedirected(ctx *azugo.Context) {
	var status int
	if ok, _ := ctx.Flash.Get("status", &status); !ok {
		ctx.Redirect("/")

		return
	}

	ctx.StatusCode(status)
	templ.Render(ctx, views.Error(http.StatusMessage(status), strings.Join(ctx.Flash.Errors(), " "), r.backURL(ctx)))
}

// notFound renders the error page for unknown routes.
func (r *router) notFound(ctx *azugo.Context) {
	ctx.StatusCode(http.StatusNotFound)
	templ.Render(ctx, views.Error(http.StatusMessage(http.StatusNotFound), "The page you asked for does not exist.", r.backURL(ctx)))
}

// backURL is the same-origin page the user came from, or home.
func (r *router) backURL(ctx *azugo.Context) string {
	if ref, base := ctx.Referer(), ctx.BaseURL(); ref == base || strings.HasPrefix(ref, base+"/") || strings.HasPrefix(ref, base+"?") {
		return ref
	}

	return "/"
}
