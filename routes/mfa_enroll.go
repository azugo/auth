package routes

import (
	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

func (h *Handler) mfaEnrollRequest(ctx *azugo.Context) (auth.MFAEnrollRequest, error) {
	in, err := readStepInput(ctx)
	if err != nil {
		return auth.MFAEnrollRequest{}, err
	}

	return auth.MFAEnrollRequest{
		Token:     h.auth.ReadSessionToken(ctx),
		Method:    ctx.Params.String("method"),
		Label:     in.Label,
		Response:  in.Response,
		ReturnTo:  in.ReturnTo,
		BaseURL:   ctx.BaseURL(),
		MountPath: h.mountPrefix,
		IP:        ctx.IP().String(),
	}, nil
}

// mfaEnroll implements POST /mfa/enroll/{method}: begin enrollment, returning the
// method-specific data (TOTP secret and otpauth URI, recovery codes, ...).
func (h *Handler) mfaEnroll(ctx *azugo.Context) {
	req, err := h.mfaEnrollRequest(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	data, err := h.auth.BeginMFAEnroll(ctx, req)
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.JSON(&struct {
		Method string         `json:"method"`
		Data   map[string]any `json:"data,omitempty"`
	}{Method: req.Method, Data: data})
}

// mfaEnrollFinish implements POST /mfa/enroll/{method}/finish: verify and persist the
// enrollment, answering its id; a pending_mfa_setup login continues to its result instead.
func (h *Handler) mfaEnrollFinish(ctx *azugo.Context) {
	req, err := h.mfaEnrollRequest(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	res, err := h.auth.FinishMFAEnroll(ctx, req)
	if err != nil {
		ctx.Error(err)

		return
	}

	if res.Login != nil {
		h.writeLoginResult(ctx, *res.Login)

		return
	}

	ctx.JSON(&struct {
		Method       string `json:"method"`
		EnrollmentID string `json:"enrollment_id"`
	}{Method: req.Method, EnrollmentID: res.EnrollmentID})
}

// mfaEnrollRevoke implements DELETE /mfa/enroll/{method}: revoke every enrollment of the
// caller in the method.
func (h *Handler) mfaEnrollRevoke(ctx *azugo.Context) {
	if err := h.auth.RevokeMFA(ctx, h.auth.ReadSessionToken(ctx), ctx.Params.String("method")); err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(http.StatusNoContent)
}

// mfaEnrollmentRevoke implements DELETE /mfa/enroll/{method}/{id}: revoke one enrollment of
// the caller.
func (h *Handler) mfaEnrollmentRevoke(ctx *azugo.Context) {
	if err := h.auth.RevokeMFAEnrollment(ctx, h.auth.ReadSessionToken(ctx), ctx.Params.String("method"), ctx.Params.String("id")); err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(http.StatusNoContent)
}
