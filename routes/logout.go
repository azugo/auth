package routes

import (
	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// logout implements GET /logout: RP-initiated browser logout, chaining the IdP end-session hop
// when the client enables FederatedLogout.
func (h *Handler) logout(ctx *azugo.Context) {
	req := auth.BrowserLogoutRequest{
		Token:     h.auth.ReadSessionToken(ctx),
		BaseURL:   ctx.BaseURL(),
		MountPath: h.mountPrefix,
		IP:        ctx.IP().String(),
		Confirmed: ctx.Method() == http.MethodPost,
	}

	if v := ctx.Query.StringOptional("post_logout_redirect_uri"); v != nil {
		req.PostLogoutRedirectURI = *v
	}

	if v := ctx.Query.StringOptional("id_token_hint"); v != nil {
		req.IDTokenHint = *v
	}

	res, err := h.auth.BrowserLogout(ctx, req)
	if err != nil {
		ctx.Error(err)

		return
	}

	if res.ConfirmationRequired {
		if h.logoutConfirmation == nil {
			ctx.Error(auth.NewOAuthError(http.StatusBadRequest, auth.ErrCodeInvalidRequest,
				"logout requires an id_token_hint or user confirmation"))

			return
		}

		h.logoutConfirmation(ctx)

		return
	}

	h.auth.WriteCookie(ctx, res.ClearCookie)
	ctx.RedirectUnsafe(res.Redirect)
}
