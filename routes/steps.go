package routes

import (
	"bytes"
	"strings"

	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// returnTo reads return_to from the query string, or from the body of a plain HTML form.
func returnTo(ctx *azugo.Context) string {
	if !bytes.HasPrefix(ctx.Request().Header.ContentType(), []byte(http.ContentTypeJSON)) {
		if v := ctx.Form.StringOptional("return_to"); v != nil {
			return *v
		}
	}

	if v := ctx.Query.StringOptional("return_to"); v != nil {
		return *v
	}

	return ""
}

// sameOriginCookie refuses a request authenticated by the session cookie that a page of another
// origin sent; a bearer token is sent deliberately and passes.
func sameOriginCookie(next azugo.RequestHandler) azugo.RequestHandler {
	return func(ctx *azugo.Context) {
		if tok, ok := strings.CutPrefix(ctx.Header.Get(http.HeaderAuthorization), "Bearer "); (!ok || tok == "") && !sameOrigin(ctx) {
			ctx.Error(auth.NewOAuthError(http.StatusForbidden, auth.ErrCodeAccessDenied, "cross-site request"))

			return
		}

		next(ctx)
	}
}

// resolveStep implements POST /steps/{name}: submit the body to the pending login step.
func (h *Handler) resolveStep(ctx *azugo.Context) {
	res, err := h.auth.ResolveStep(ctx, auth.StepRequest{
		Token:     h.auth.ReadSessionToken(ctx),
		Name:      ctx.Params.String("name"),
		Payload:   ctx.Body.Bytes(),
		ReturnTo:  returnTo(ctx),
		BaseURL:   ctx.BaseURL(),
		MountPath: h.mountPrefix,
		IP:        ctx.IP().String(),
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	h.writeLoginResult(ctx, res)
}

// switchSession implements POST /session/switch: apply the selection in the body (a JSON
// object, or form fields) to the active session.
func (h *Handler) switchSession(ctx *azugo.Context) {
	var selection map[string]any

	if bytes.HasPrefix(ctx.Request().Header.ContentType(), []byte(http.ContentTypeJSON)) {
		if len(ctx.Body.Bytes()) > 0 {
			if err := ctx.Body.JSON(&selection); err != nil {
				ctx.Error(err)

				return
			}
		}
	} else {
		selection = make(map[string]any)

		for k, v := range ctx.Request().PostArgs().All() {
			if key := string(k); key != "return_to" {
				selection[key] = string(v)
			}
		}
	}

	res, err := h.auth.SwitchSession(ctx, auth.SwitchSessionRequest{
		Token:     h.auth.ReadSessionToken(ctx),
		Selection: selection,
		ReturnTo:  returnTo(ctx),
		BaseURL:   ctx.BaseURL(),
		MountPath: h.mountPrefix,
		IP:        ctx.IP().String(),
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	h.writeLoginResult(ctx, res)
}

// verifyContact implements POST /account/contact/verify: present the delivered proof of a
// contact verification request outside of a login.
func (h *Handler) verifyContact(ctx *azugo.Context) {
	in, _, err := h.readAccountInput(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	if err := h.auth.VerifyContact(ctx, auth.ContactVerificationRequest{Request: in.Request, Response: in.Response, IP: ctx.IP().String()}); err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(http.StatusNoContent)
}

// contacts implements GET /account/contacts: the caller's contacts by channel.
func (h *Handler) contacts(ctx *azugo.Context) {
	contacts, err := h.auth.ListContacts(ctx, h.auth.ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.JSON(contacts)
}

// addContact implements POST /account/contacts: start verifying a new address, the proof going
// to POST /account/contact/verify.
func (h *Handler) addContact(ctx *azugo.Context) {
	in, _, err := h.readAccountInput(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	res, err := h.auth.AddContact(ctx, auth.ContactRequest{Token: h.auth.ReadSessionToken(ctx), Channel: in.Channel, Address: in.Address, IP: ctx.IP().String()})
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(http.StatusAccepted)
	ctx.JSON(&struct {
		Request     string         `json:"request"`
		Interaction string         `json:"interaction"`
		Data        map[string]any `json:"data,omitempty"`
	}{Request: res.Request, Interaction: res.Interaction, Data: res.Data})
}

// primaryContact implements POST /account/contacts/primary.
func (h *Handler) primaryContact(ctx *azugo.Context) {
	in, _, err := h.readAccountInput(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	if err := h.auth.SetPrimaryContact(ctx, auth.ContactRequest{Token: h.auth.ReadSessionToken(ctx), Channel: in.Channel, Address: in.Address, IP: ctx.IP().String()}); err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(http.StatusNoContent)
}

// removeContact implements POST /account/contacts/remove.
func (h *Handler) removeContact(ctx *azugo.Context) {
	in, _, err := h.readAccountInput(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	if err := h.auth.RemoveContact(ctx, auth.ContactRequest{Token: h.auth.ReadSessionToken(ctx), Channel: in.Channel, Address: in.Address, IP: ctx.IP().String()}); err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(http.StatusNoContent)
}

// reauth implements POST /session/reauth: start re-authenticating the active session for an
// action.
func (h *Handler) reauth(ctx *azugo.Context) {
	in, err := readStepInput(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	res, err := h.auth.BeginReauth(ctx, auth.ReauthRequest{Token: h.auth.ReadSessionToken(ctx), Action: in.Action, Method: in.Method, IP: ctx.IP().String()})
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.JSON(&struct {
		Available   []string       `json:"available"`
		Selected    string         `json:"selected"`
		Interaction string         `json:"interaction"`
		Data        map[string]any `json:"data,omitempty"`
		Password    bool           `json:"password,omitempty"`
	}{
		Available:   res.Available,
		Selected:    res.Selected,
		Interaction: res.Interaction,
		Data:        res.Data,
		Password:    res.Password,
	})
}

// reauthVerify implements POST /session/reauth/verify: present the password or MFA proof.
func (h *Handler) reauthVerify(ctx *azugo.Context) {
	in, err := readStepInput(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	if err := h.auth.VerifyReauth(ctx, auth.ReauthVerifyRequest{Token: h.auth.ReadSessionToken(ctx), Password: in.Password, Response: in.Response, IP: ctx.IP().String()}); err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(http.StatusNoContent)
}
