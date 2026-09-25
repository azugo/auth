package routes

import (
	"bytes"

	"azugo.io/auth"
	"azugo.io/auth/mfa"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// stepInput is the JSON body of the MFA step and enrollment endpoints. A form-encoded body is
// accepted too, with code and device as the response fields.
type stepInput struct {
	Method   string         `json:"method"`
	Label    string         `json:"label"`
	Response map[string]any `json:"response"`
	ReturnTo string         `json:"return_to"`
}

// readStepInput parses the request body as JSON, or as form fields for plain HTML forms.
func readStepInput(ctx *azugo.Context) (stepInput, error) {
	var in stepInput

	if bytes.HasPrefix(ctx.Request().Header.ContentType(), []byte(http.ContentTypeJSON)) {
		if len(ctx.Body.Bytes()) == 0 {
			return in, nil
		}

		return in, ctx.Body.JSON(&in)
	}

	if v := ctx.Form.StringOptional("method"); v != nil {
		in.Method = *v
	}

	if v := ctx.Form.StringOptional("return_to"); v != nil {
		in.ReturnTo = *v
	}

	if v := ctx.Form.StringOptional("label"); v != nil {
		in.Label = *v
	}

	if v := ctx.Form.StringOptional("code"); v != nil {
		in.Response = map[string]any{"code": *v}
	}

	if v := ctx.Form.StringOptional("device"); v != nil {
		if in.Response == nil {
			in.Response = make(map[string]any, 1)
		}

		in.Response["device"] = *v
	}

	return in, nil
}

func (h *Handler) mfaStepRequest(ctx *azugo.Context) (auth.MFAStepRequest, error) {
	in, err := readStepInput(ctx)
	if err != nil {
		return auth.MFAStepRequest{}, err
	}

	return auth.MFAStepRequest{
		Token:     h.auth.ReadSessionToken(ctx),
		Method:    in.Method,
		Response:  in.Response,
		ReturnTo:  in.ReturnTo,
		BaseURL:   ctx.BaseURL(),
		MountPath: h.mountPrefix,
		IP:        ctx.IP().String(),
	}, nil
}

// mfaStep runs one step-token call and writes its LoginResult.
func (h *Handler) mfaStep(ctx *azugo.Context, call func(auth.MFAStepRequest) (auth.LoginResult, error)) {
	req, err := h.mfaStepRequest(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	res, err := call(req)
	if err != nil {
		ctx.Error(err)

		return
	}

	h.writeLoginResult(ctx, res)
}

// mfaVerify implements POST /mfa/verify: submit the code/assertion for the selected method.
func (h *Handler) mfaVerify(ctx *azugo.Context) {
	h.mfaStep(ctx, func(req auth.MFAStepRequest) (auth.LoginResult, error) { return h.auth.VerifyMFA(ctx, req) })
}

// mfaBegin implements POST /mfa/begin: select or switch the active method.
func (h *Handler) mfaBegin(ctx *azugo.Context) {
	h.mfaStep(ctx, func(req auth.MFAStepRequest) (auth.LoginResult, error) { return h.auth.BeginMFA(ctx, req) })
}

// mfaResend implements POST /mfa/resend: re-open the selected challenge.
func (h *Handler) mfaResend(ctx *azugo.Context) {
	h.mfaStep(ctx, func(req auth.MFAStepRequest) (auth.LoginResult, error) { return h.auth.ResendMFA(ctx, req) })
}

// mfaStatus implements GET /mfa/status: poll an async factor.
func (h *Handler) mfaStatus(ctx *azugo.Context) {
	req := auth.MFAStepRequest{
		Token:     h.auth.ReadSessionToken(ctx),
		BaseURL:   ctx.BaseURL(),
		MountPath: h.mountPrefix,
		IP:        ctx.IP().String(),
	}

	if v := ctx.Query.StringOptional("return_to"); v != nil {
		req.ReturnTo = *v
	}

	res, err := h.auth.MFAStatus(ctx, req)
	if err != nil {
		ctx.Error(err)

		return
	}

	h.writeLoginResult(ctx, res)
}

// mfaCallback implements POST /mfa/callback/{method}: the vendor webhook of a
// mfa.CallbackHandler method.
func (h *Handler) mfaCallback(ctx *azugo.Context) {
	m, err := h.auth.MFAMethods().Get(ctx, ctx.Params.String("method"))
	if err != nil {
		ctx.Error(auth.NewOAuthErrorFrom(err))

		return
	}

	cb, ok := m.(mfa.CallbackHandler)
	if !ok {
		ctx.Error(auth.NewOAuthErrorFrom(mfa.ErrUnknownMethod))

		return
	}

	if err := cb.HandleCallback(ctx); err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(http.StatusNoContent)
}

// mfaMethods implements GET /mfa/methods: the methods offered to the caller, flagged by
// enrollment.
func (h *Handler) mfaMethods(ctx *azugo.Context) {
	out, err := h.auth.ListMFAMethods(ctx, h.auth.ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.JSON(out)
}
