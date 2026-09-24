package routes

import (
	"example/portal/views"

	"azugo.io/auth"
	"azugo.io/auth/session"

	"azugo.io/azugo"
	"azugo.io/templ"
)

// stepRequest builds the step-token call for the pending login behind the session cookie.
func (r *router) stepRequest(ctx *azugo.Context, returnTo string) auth.MFAStepRequest {
	return auth.MFAStepRequest{
		Token:    r.Auth().ReadSessionToken(ctx),
		ReturnTo: returnTo,
		BaseURL:  ctx.BaseURL(),
		IP:       ctx.IP().String(),
	}
}

// mfaPage renders the second-factor prompt for a login held at pending_mfa.
func (r *router) mfaPage(ctx *azugo.Context) {
	returnTo := ""
	if v := ctx.Query.StringOptional("return_to"); v != nil {
		returnTo = *v
	}

	res, err := r.Auth().MFAStatus(ctx, r.stepRequest(ctx, returnTo))
	if err != nil {
		if !r.fatal(ctx, err, returnTo) {
			ctx.Error(err)
		}

		return
	}

	if res.Status == session.StatusActive {
		r.finishStep(ctx, res)

		return
	}

	transaction, _ := res.Data["transaction"].(string)

	templ.Render(ctx, views.MFA(res.Available, res.Selected, res.Interaction, transaction, returnTo, ctx.Flash.FieldErrorFor("code")))
}

// finishStep applies a step result.
func (r *router) finishStep(ctx *azugo.Context, res auth.LoginResult) {
	r.Auth().WriteCookie(ctx, res.Cookie)
	ctx.Redirect(res.ReturnTo)
}

// mfaVerify submits the code for the selected method.
func (r *router) mfaVerify(ctx *azugo.Context) {
	returnTo := ""
	if v := ctx.Form.StringOptional("return_to"); v != nil {
		returnTo = *v
	}

	req := r.stepRequest(ctx, returnTo)
	if v := ctx.Form.StringOptional("code"); v != nil {
		req.Response = map[string]any{"code": *v}
	}

	res, err := r.Auth().VerifyMFA(ctx, req)
	if err != nil {
		if r.fatal(ctx, err, returnTo) {
			return
		}

		ctx.Flash.FieldError("code", errorMessage(err, "Invalid code. Please try again."))
		ctx.Redirect(pageURL("/mfa", returnTo))

		return
	}

	r.finishStep(ctx, res)
}

// mfaBegin switches the pending login to another enrolled method.
func (r *router) mfaBegin(ctx *azugo.Context) {
	returnTo := ""
	if v := ctx.Form.StringOptional("return_to"); v != nil {
		returnTo = *v
	}

	req := r.stepRequest(ctx, returnTo)
	if v := ctx.Form.StringOptional("method"); v != nil {
		req.Method = *v
	}

	res, err := r.Auth().BeginMFA(ctx, req)
	if err != nil {
		if r.fatal(ctx, err, returnTo) {
			return
		}

		ctx.Flash.FieldError("code", errorMessage(err, "That method is not available."))
		ctx.Redirect(pageURL("/mfa", returnTo))

		return
	}

	r.finishStep(ctx, res)
}
