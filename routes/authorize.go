package routes

import (
	"azugo.io/auth"

	"azugo.io/azugo"
)

// authorizeCode implements GET /authorize: the OIDC authorization-code flow endpoint.
func (h *Handler) authorizeCode(ctx *azugo.Context) {
	req := auth.AuthorizeRequest{
		SessionToken: ctx.Cookie.Get(h.auth.Config().CookieName),
	}

	if v := ctx.Query.StringOptional("response_type"); v != nil {
		req.ResponseType = *v
	}

	if v := ctx.Query.StringOptional("client_id"); v != nil {
		req.ClientID = *v
	}

	if v := ctx.Query.StringOptional("redirect_uri"); v != nil {
		req.RedirectURI = *v
	}

	if v := ctx.Query.StringOptional("scope"); v != nil {
		req.Scope = *v
	}

	if v := ctx.Query.StringOptional("state"); v != nil {
		req.State = *v
	}

	if v := ctx.Query.StringOptional("nonce"); v != nil {
		req.Nonce = *v
	}

	if v := ctx.Query.StringOptional("acr_values"); v != nil {
		req.ACRValues = *v
	}

	if v := ctx.Query.StringOptional("code_challenge"); v != nil {
		req.CodeChallenge = *v
	}

	if v := ctx.Query.StringOptional("code_challenge_method"); v != nil {
		req.CodeChallengeMethod = *v
	}

	res, err := h.auth.Authorize(ctx, req)
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.RedirectUnsafe(res.Redirect)
}

// authorize implements POST /authorize: the portal's silent re-authentication over the
// existing session cookie.
func (h *Handler) authorize(ctx *azugo.Context) {
	returnTo := ""
	if v := ctx.Query.StringOptional("return_to"); v != nil {
		returnTo = *v
	}

	res, err := h.auth.Refresh(ctx, auth.RefreshRequest{
		Token:      ctx.Cookie.Get(h.auth.Config().CookieName),
		ReturnTo:   returnTo,
		RequestTLS: ctx.IsTLS(),
		BaseURL:    ctx.BaseURL(),
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	h.writeLoginResult(ctx, res)
}
