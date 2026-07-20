package routes

import (
	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// getSession implements GET /session: a keepalive/health check over the presented token.
func (h *Handler) getSession(ctx *azugo.Context) {
	if _, _, err := h.auth.IntrospectToken(ctx, h.auth.ReadSessionToken(ctx)); err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(http.StatusOK)
}

// deleteSession implements DELETE /session: the authoritative, non-redirecting logout for
// SPA/API clients.
func (h *Handler) deleteSession(ctx *azugo.Context) {
	res, err := h.auth.Logout(ctx, auth.LogoutRequest{
		Token:      h.auth.ReadSessionToken(ctx),
		RequestTLS: ctx.IsTLS(),
		BasePath:   ctx.BasePath(),
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	h.auth.WriteCookie(ctx, res.ClearCookie)
	ctx.StatusCode(http.StatusNoContent)
}
