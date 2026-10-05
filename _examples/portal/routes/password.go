package routes

import (
	"errors"

	"example/portal/views"

	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/templ"
)

// passwordForm renders the password page: a signed-in user changes their password, a login
// held at pending_password_change sets the new one it must have.
func (r *router) passwordForm(ctx *azugo.Context) {
	returnTo := ""
	if v := ctx.Query.StringOptional("return_to"); v != nil {
		returnTo = *v
	}

	templ.Render(ctx, views.Password(ctx.User().Authorized(), returnTo, views.PasswordErrors{
		Current: ctx.Flash.FieldErrorFor("current_password"),
		New:     ctx.Flash.FieldErrorFor("new_password"),
		Confirm: ctx.Flash.FieldErrorFor("confirm_password"),
	}))
}

// changePassword submits the password form to the service tier.
func (r *router) changePassword(ctx *azugo.Context) {
	req := auth.PasswordChangeRequest{
		Token:   r.Auth().ReadSessionToken(ctx),
		BaseURL: ctx.BaseURL(),
		IP:      ctx.IP().String(),
	}

	if v := ctx.Form.StringOptional("return_to"); v != nil {
		req.ReturnTo = *v
	}

	if v := ctx.Form.StringOptional("current_password"); v != nil {
		req.CurrentPassword = *v
	}

	if v := ctx.Form.StringOptional("new_password"); v != nil {
		req.NewPassword = *v
	}

	if v := ctx.Form.StringOptional("keep_other_sessions"); v != nil {
		req.KeepOtherSessions = *v != ""
	}

	if v := ctx.Form.StringOptional("confirm_password"); v == nil || *v != req.NewPassword {
		ctx.Flash.FieldError("confirm_password", "The passwords do not match.")
		ctx.Redirect(pageURL("/password", req.ReturnTo))

		return
	}

	res, err := r.Auth().ChangePassword(ctx, req)
	if err != nil {
		if r.fatal(ctx, err, req.ReturnTo) {
			return
		}

		// A rejected credential is the current password; anything else is about the new one.
		field := "new_password"

		var oe *auth.OAuthError
		if errors.As(err, &oe) && oe.Code == auth.ErrCodeInvalidGrant {
			field = "current_password"
		}

		ctx.Flash.FieldError(field, errorMessage(err, "The current password is wrong."))
		ctx.Redirect(pageURL("/password", req.ReturnTo))

		return
	}

	r.finishStep(ctx, res, req.ReturnTo)
}
