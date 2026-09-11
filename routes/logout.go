package routes

import (
	"azugo.io/auth"

	"azugo.io/azugo"
)

// logout implements GET /logout: RP-initiated browser logout, chaining the IdP end-session hop
// when the client enables FederatedLogout.
func (h *Handler) logout(ctx *azugo.Context) {
	req := auth.BrowserLogoutRequest{
		Token:      h.auth.ReadSessionToken(ctx),
		RequestTLS: ctx.IsTLS(),
		BaseURL:    ctx.BaseURL(),
		MountPath:  h.mountPrefix,
		IP:         ctx.IP().String(),
	}

	if v := ctx.Query.StringOptional("post_logout_redirect_uri"); v != nil {
		req.PostLogoutRedirectURI = *v
	}

	res, err := h.auth.BrowserLogout(ctx, req)
	if err != nil {
		ctx.Error(err)

		return
	}

	h.auth.WriteCookie(ctx, res.ClearCookie)
	ctx.RedirectUnsafe(res.Redirect)
}
