package routes

import (
	"bytes"
	"strings"

	"azugo.io/auth"
	"azugo.io/auth/reset"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// accountInput is the JSON body of the account endpoints. A form-encoded body is accepted
// too, with the client authenticated as at /token.
type accountInput struct {
	ClientID          string         `json:"client_id"`
	ClientSecret      string         `json:"client_secret"`
	Username          string         `json:"username"`
	Email             string         `json:"email"`
	Password          string         `json:"password"`
	Extra             map[string]any `json:"extra"`
	CurrentPassword   string         `json:"current_password"`
	NewPassword       string         `json:"new_password"`
	KeepOtherSessions bool           `json:"keep_other_sessions"`
	Identifier        string         `json:"identifier"`
	Method            string         `json:"method"`
	ResetToken        string         `json:"reset_token"`
	Response          map[string]any `json:"response"`
	ReturnTo          string         `json:"return_to"`
}

// resetToken returns the reset_token from the body or the Authorization header.
func (in accountInput) resetToken(ctx *azugo.Context) string {
	if in.ResetToken != "" {
		return in.ResetToken
	}

	if tok, ok := strings.CutPrefix(ctx.Header.Get(http.HeaderAuthorization), "Bearer "); ok {
		return tok
	}

	return ""
}

// readAccountInput parses the request body as JSON, or as form fields for plain HTML forms.
func (h *Handler) readAccountInput(ctx *azugo.Context) (accountInput, auth.ClientCredentials, error) {
	var in accountInput

	if bytes.HasPrefix(ctx.Request().Header.ContentType(), []byte(http.ContentTypeJSON)) {
		if len(ctx.Body.Bytes()) > 0 {
			if err := ctx.Body.JSON(&in); err != nil {
				return in, auth.ClientCredentials{}, err
			}
		}

		return in, auth.ClientCredentials{ClientID: in.ClientID, Secret: in.ClientSecret}, nil
	}

	creds, err := h.clientCredentials(ctx)
	if err != nil {
		return in, auth.ClientCredentials{}, err
	}

	if v := ctx.Form.StringOptional("username"); v != nil {
		in.Username = *v
	}

	if v := ctx.Form.StringOptional("email"); v != nil {
		in.Email = *v
	}

	if v := ctx.Form.StringOptional("password"); v != nil {
		in.Password = *v
	}

	if v := ctx.Form.StringOptional("current_password"); v != nil {
		in.CurrentPassword = *v
	}

	if v := ctx.Form.StringOptional("new_password"); v != nil {
		in.NewPassword = *v
	}

	if v := ctx.Form.StringOptional("keep_other_sessions"); v != nil {
		in.KeepOtherSessions = *v != ""
	}

	if v := ctx.Form.StringOptional("identifier"); v != nil {
		in.Identifier = *v
	}

	if v := ctx.Form.StringOptional("method"); v != nil {
		in.Method = *v
	}

	if v := ctx.Form.StringOptional("reset_token"); v != nil {
		in.ResetToken = *v
	}

	if v := ctx.Form.StringOptional("return_to"); v != nil {
		in.ReturnTo = *v
	}

	// A plain form carries the proof as code or token.
	if v := ctx.Form.StringOptional("code"); v != nil {
		in.Response = map[string]any{"code": *v}
	}

	if v := ctx.Form.StringOptional("token"); v != nil {
		if in.Response == nil {
			in.Response = make(map[string]any, 1)
		}

		in.Response["token"] = *v
	}

	return in, creds, nil
}

// writeResetResult writes a reset in progress with the given status code.
func writeResetResult(ctx *azugo.Context, status int, res auth.PasswordResetResult) {
	ctx.StatusCode(status)
	ctx.JSON(&struct {
		Status      reset.VerifyResult `json:"status"`
		ResetToken  string             `json:"reset_token"`
		Available   []string           `json:"available"`
		Selected    string             `json:"selected"`
		Interaction string             `json:"interaction"`
		Data        map[string]any     `json:"data,omitempty"`
	}{Status: res.Status, ResetToken: res.Token, Available: res.Available, Selected: res.Selected, Interaction: res.Interaction, Data: res.Data})
}

// register implements POST /account/register: create the account and, per the client's
// RegistrationPolicy, sign it in or answer 201 with its ID.
func (h *Handler) register(ctx *azugo.Context) {
	in, creds, err := h.readAccountInput(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	res, err := h.auth.Register(ctx, auth.RegisterRequest{
		Credentials: creds,
		Username:    in.Username,
		Email:       in.Email,
		Password:    in.Password,
		Extra:       in.Extra,
		ReturnTo:    in.ReturnTo,
		BaseURL:     ctx.BaseURL(),
		MountPath:   h.mountPrefix,
		IP:          ctx.IP().String(),
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	if res.Login != nil {
		h.writeLoginResult(ctx, *res.Login)

		return
	}

	ctx.StatusCode(http.StatusCreated)
	ctx.JSON(&struct {
		UserID string `json:"user_id"`
	}{
		UserID: res.UserID,
	})
}

// changePassword implements POST /account/password: change the password of an active session
// (current password verified) or complete a pending_password_change login.
func (h *Handler) changePassword(ctx *azugo.Context) {
	in, _, err := h.readAccountInput(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	res, err := h.auth.ChangePassword(ctx, auth.PasswordChangeRequest{
		Token:             h.auth.ReadSessionToken(ctx),
		CurrentPassword:   in.CurrentPassword,
		NewPassword:       in.NewPassword,
		KeepOtherSessions: in.KeepOtherSessions,
		ReturnTo:          in.ReturnTo,
		BaseURL:           ctx.BaseURL(),
		MountPath:         h.mountPrefix,
		IP:                ctx.IP().String(),
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	h.writeLoginResult(ctx, res)
}

// requestPasswordReset implements POST /account/password/reset: always 202 with the same
// shape, so the response never tells whether the account exists.
func (h *Handler) requestPasswordReset(ctx *azugo.Context) {
	in, creds, err := h.readAccountInput(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	res, err := h.auth.RequestPasswordReset(ctx, auth.PasswordResetRequest{
		Credentials: creds,
		Identifier:  in.Identifier,
		Method:      in.Method,
		BaseURL:     ctx.BaseURL(),
		MountPath:   h.mountPrefix,
		IP:          ctx.IP().String(),
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	writeResetResult(ctx, http.StatusAccepted, res)
}

// beginPasswordReset implements POST /account/password/reset/begin: switch the method or
// re-open the selected one.
func (h *Handler) beginPasswordReset(ctx *azugo.Context) {
	in, _, err := h.readAccountInput(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	res, err := h.auth.BeginPasswordReset(ctx, auth.PasswordResetStepRequest{Token: in.resetToken(ctx), Method: in.Method, IP: ctx.IP().String()})
	if err != nil {
		ctx.Error(err)

		return
	}

	writeResetResult(ctx, http.StatusAccepted, res)
}

// passwordResetStatus implements GET /account/password/reset/status: poll an asynchronous
// method, the reset_token in the Authorization header.
func (h *Handler) passwordResetStatus(ctx *azugo.Context) {
	res, err := h.auth.PasswordResetStatus(ctx, auth.PasswordResetStepRequest{Token: accountInput{}.resetToken(ctx), IP: ctx.IP().String()})
	if err != nil {
		ctx.Error(err)

		return
	}

	writeResetResult(ctx, http.StatusOK, res)
}

// resetPassword implements POST /account/password/reset/confirm: verify the proof, set the
// new password and sign the user in.
func (h *Handler) resetPassword(ctx *azugo.Context) {
	in, _, err := h.readAccountInput(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	res, err := h.auth.ResetPassword(ctx, auth.PasswordResetConfirmRequest{
		Token:       in.resetToken(ctx),
		Response:    in.Response,
		NewPassword: in.NewPassword,
		ReturnTo:    in.ReturnTo,
		BaseURL:     ctx.BaseURL(),
		MountPath:   h.mountPrefix,
		IP:          ctx.IP().String(),
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	h.writeLoginResult(ctx, res)
}

// profile implements GET /account/profile.
func (h *Handler) profile(ctx *azugo.Context) {
	data, err := h.auth.Profile(ctx, h.auth.ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.JSON(data)
}

// updateProfile implements PUT /account/profile: the JSON object body is passed through.
func (h *Handler) updateProfile(ctx *azugo.Context) {
	var data map[string]any
	if err := ctx.Body.JSON(&data); err != nil {
		ctx.Error(err)

		return
	}

	if err := h.auth.UpdateProfile(ctx, h.auth.ReadSessionToken(ctx), data); err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(http.StatusNoContent)
}
