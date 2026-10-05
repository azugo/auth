package routes

import (
	"strings"

	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// sameOrigin reports whether a POST was sent by a page of this origin, from the browser's own
// Fetch Metadata or, failing that, its Origin header.
func sameOrigin(ctx *azugo.Context) bool {
	switch ctx.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
		origin := ctx.Header.Get(http.HeaderOrigin)
		base := ctx.BaseURL()

		return origin != "" && (base == origin || strings.HasPrefix(base, origin+"/"))
	default:
		return false
	}
}

// logout implements GET /logout: RP-initiated browser logout, chaining the IdP end-session hop
// when the client enables FederatedLogout.
func (h *Handler) logout(ctx *azugo.Context) {
	req := auth.BrowserLogoutRequest{
		Token:     h.auth.ReadSessionToken(ctx),
		BaseURL:   ctx.BaseURL(),
		MountPath: h.mountPrefix,
		IP:        ctx.IP().String(),
		Confirmed: ctx.Method() == http.MethodPost && sameOrigin(ctx),
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
