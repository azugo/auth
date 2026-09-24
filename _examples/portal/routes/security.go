package routes

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"strings"

	"example/portal/views"

	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/templ"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

// securityPage lists the caller's MFA methods.
func (r *router) securityPage(ctx *azugo.Context) {
	var enrollment *views.Enrollment

	var e views.Enrollment
	if ok, _ := ctx.Flash.Get("enrollment", &e); ok {
		enrollment = &e

		if e.URI != "" {
			code, err := qr.Encode(e.URI, qr.M, qr.Auto)
			if err != nil {
				ctx.Error(err)

				return
			}

			if code, err = barcode.Scale(code, 200, 200); err != nil {
				ctx.Error(err)

				return
			}

			var buf bytes.Buffer
			if err := png.Encode(&buf, code); err != nil {
				ctx.Error(err)

				return
			}

			enrollment.QR = "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
		}
	}

	message := ctx.Flash.FieldErrorFor("code")
	if errs := ctx.Flash.Errors(); message == "" && len(errs) > 0 {
		message = errs[0]
	}

	r.renderSecurity(ctx, enrollment, message)
}

func (r *router) renderSecurity(ctx *azugo.Context, enrollment *views.Enrollment, errorMessage string) {
	methods, err := r.Auth().ListMFAMethods(ctx, r.Auth().ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	templ.Render(ctx, views.Security(methods, enrollment, errorMessage))
}

// mfaEnroll begins enrolling the caller in {method} and hands what the user must save.
func (r *router) mfaEnroll(ctx *azugo.Context) {
	method := ctx.Params.String("method")

	data, err := r.Auth().BeginMFAEnroll(ctx, auth.MFAEnrollRequest{Token: r.Auth().ReadSessionToken(ctx), Method: method})
	if err != nil {
		if r.fatal(ctx, err, "/security") {
			return
		}

		ctx.Flash.Error(errorMessage(err, "Could not start the enrollment."))
		ctx.Redirect("/security")

		return
	}

	enrollment := &views.Enrollment{Method: method}
	enrollment.Secret, _ = data["secret"].(string)
	enrollment.URI, _ = data["uri"].(string)
	enrollment.Codes, _ = data["codes"].([]string)
	enrollment.Required, _ = data["required"].([]string)

	_ = ctx.Flash.Set("enrollment", enrollment)
	ctx.Redirect("/security")
}

// mfaEnrollFinish confirms the enrollment.
func (r *router) mfaEnrollFinish(ctx *azugo.Context) {
	method := ctx.Params.String("method")

	response := map[string]any{}
	if v := ctx.Form.StringOptional("code"); v != nil {
		response["code"] = *v
	}

	if v := ctx.Form.StringOptional("device"); v != nil {
		response["device"] = *v
	}

	label := ""
	if v := ctx.Form.StringOptional("label"); v != nil {
		label = *v
	}

	_, err := r.Auth().FinishMFAEnroll(ctx, auth.MFAEnrollRequest{
		Token:    r.Auth().ReadSessionToken(ctx),
		Method:   method,
		Label:    label,
		Response: response,
		IP:       ctx.IP().String(),
	})
	if err == nil {
		ctx.Redirect("/security")

		return
	}

	if r.fatal(ctx, err, "/security") {
		return
	}

	ctx.Flash.FieldError("code", errorMessage(err, "Invalid code. Check your authenticator app and try again."))

	// The hidden fields are client-supplied: only an otpauth URI is ever rendered back.
	secret := ctx.Form.StringOptional("secret")
	uri := ctx.Form.StringOptional("uri")

	if secret != nil && uri != nil && strings.HasPrefix(*uri, "otpauth://") {
		_ = ctx.Flash.Set("enrollment", views.Enrollment{Method: method, Secret: *secret, URI: *uri})
	}

	ctx.Redirect("/security")
}

// mfaRevoke removes one of the caller's enrollments in {method}.
func (r *router) mfaRevoke(ctx *azugo.Context) {
	if err := r.Auth().RevokeMFAEnrollment(ctx, r.Auth().ReadSessionToken(ctx), ctx.Params.String("method"), ctx.Params.String("id")); err != nil {
		if r.fatal(ctx, err, "/security") {
			return
		}

		ctx.Flash.Error(errorMessage(err, "Could not disable the method."))
		ctx.Redirect("/security")

		return
	}

	ctx.Redirect("/security")
}
