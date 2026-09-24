package routes

import (
	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// revoke implements POST /revoke (RFC 7009).
func (h *Handler) revoke(ctx *azugo.Context) {
	creds, err := h.clientCredentials(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	req := auth.RevokeTokenRequest{
		Credentials: creds,
		BaseURL:     ctx.BaseURL(),
		MountPath:   h.mountPrefix,
		IP:          ctx.IP().String(),
	}

	if v := ctx.Form.StringOptional("token"); v != nil {
		req.Token = *v
	}

	if err := h.auth.RevokeToken(ctx, req); err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(http.StatusOK)
}

// introspect implements POST /introspect (RFC 7662) for authenticated confidential clients.
func (h *Handler) introspect(ctx *azugo.Context) {
	creds, err := h.clientCredentials(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	req := auth.IntrospectRequest{
		Credentials: creds,
		BaseURL:     ctx.BaseURL(),
		MountPath:   h.mountPrefix,
	}

	if v := ctx.Form.StringOptional("token"); v != nil {
		req.Token = *v
	}

	res, err := h.auth.Introspect(ctx, req)
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.JSON(&res)
}
