package routes

import (
	"time"

	"azugo.io/auth"
	"azugo.io/auth/provider"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// externalLogin implements GET /external/{provider}/login: redirects to the IdP.
func (h *Handler) externalLogin(ctx *azugo.Context) {
	clientID, err := ctx.Query.String("client_id")
	if err != nil {
		ctx.Error(err)

		return
	}

	req := auth.ExternalLoginRequest{
		Provider: ctx.Params.String("provider"),
		ClientID: clientID,
	}

	if v := ctx.Query.StringOptional("return_to"); v != nil {
		req.ReturnTo = *v
	}

	res, err := h.auth.BeginExternalLogin(ctx, req)
	if err != nil {
		ctx.Error(err)

		return
	}

	// Provider URLs are off-origin by nature
	ctx.RedirectUnsafe(res.Redirect)
}

// externalCallback implements GET /external/{provider}/callback: validates the IdP redirect
// and finalizes (or defers) the login, or completes the linking ceremony.
func (h *Handler) externalCallback(ctx *azugo.Context) {
	req := auth.ExternalCallbackRequest{
		Provider:   ctx.Params.String("provider"),
		RequestTLS: ctx.IsTLS(),
		BaseURL:    ctx.BaseURL(),
		MountPath:  h.mountPrefix,
		IP:         ctx.IP().String(),
	}

	for key, dst := range map[string]*string{
		"state": &req.State, "code": &req.Code,
		"error": &req.Error, "error_description": &req.ErrorDescription,
	} {
		if v := ctx.Query.StringOptional(key); v != nil {
			*dst = *v
		}
	}

	res, err := h.auth.ExternalCallback(ctx, req)
	if err != nil {
		ctx.Error(err)

		return
	}

	switch {
	case res.Login != nil:
		h.writeLoginResult(ctx, *res.Login)
	case res.Redirect != "":
		// The IdP end-session endpoint is off-origin by nature.
		ctx.RedirectUnsafe(res.Redirect)
	case res.ReturnTo != "":
		ctx.Redirect(res.ReturnTo)
	case res.Link != nil:
		ctx.JSON(newIdentityResponse(res.Link))
	default:
		ctx.StatusCode(http.StatusNoContent)
	}
}

// externalLogoutCallback implements GET /external/{provider}/logout/callback: the IdP redirect
// target after RP-initiated logout.
func (h *Handler) externalLogoutCallback(ctx *azugo.Context) {
	req := auth.ExternalLogoutCallbackRequest{
		Provider:   ctx.Params.String("provider"),
		RequestTLS: ctx.IsTLS(),
		BaseURL:    ctx.BaseURL(),
		MountPath:  h.mountPrefix,
		IP:         ctx.IP().String(),
	}

	if v := ctx.Query.StringOptional("state"); v != nil {
		req.State = *v
	}

	res, err := h.auth.ExternalLogoutCallback(ctx, req)
	if err != nil {
		ctx.Error(err)

		return
	}

	if res.Login != nil {
		h.writeLoginResult(ctx, *res.Login)

		return
	}

	// Provider URLs are off-origin by nature
	ctx.RedirectUnsafe(res.Redirect)
}

// externalLink implements GET /external/{provider}/link: the account-linking ceremony for the
// authenticated caller.
func (h *Handler) externalLink(ctx *azugo.Context) {
	req := auth.ExternalLinkRequest{
		Provider: ctx.Params.String("provider"),
		Token:    h.auth.ReadSessionToken(ctx),
	}

	if v := ctx.Query.StringOptional("return_to"); v != nil {
		req.ReturnTo = *v
	}

	res, err := h.auth.BeginExternalLink(ctx, req)
	if err != nil {
		ctx.Error(err)

		return
	}

	// Provider URLs are off-origin by nature
	ctx.RedirectUnsafe(res.Redirect)
}

type identityResponse struct {
	ID         string     `json:"id"`
	Provider   string     `json:"provider"`
	Subject    string     `json:"subject"`
	Email      string     `json:"email,omitempty"`
	LinkedAt   time.Time  `json:"linked_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

func newIdentityResponse(l *provider.IdentityLink) identityResponse {
	return identityResponse{
		ID:         l.ID,
		Provider:   l.Provider,
		Subject:    l.Subject,
		Email:      l.Email,
		LinkedAt:   l.LinkedAt,
		LastUsedAt: l.LastUsedAt,
	}
}

// listIdentities implements GET /external/identities: the caller's linked external identities.
func (h *Handler) listIdentities(ctx *azugo.Context) {
	info, _, err := h.auth.IntrospectToken(ctx, h.auth.ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	providerName := ""
	if v := ctx.Query.StringOptional("provider"); v != nil {
		providerName = *v
	}

	links, pages, err := h.auth.ListIdentities(ctx, info.ID, providerName, ctx.Paging())
	if err != nil {
		ctx.Error(err)

		return
	}

	out := make([]identityResponse, len(links))
	for i, l := range links {
		out[i] = newIdentityResponse(l)
	}

	ctx.SetPaging(map[string]string{"type": "identities"}, pages)
	ctx.JSON(out)
}

// unlinkIdentity implements DELETE /external/{provider}/identities/{id}: caller-owned unlink.
func (h *Handler) unlinkIdentity(ctx *azugo.Context) {
	info, _, err := h.auth.IntrospectToken(ctx, h.auth.ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	if err := h.auth.UnlinkIdentity(ctx, info.ID, ctx.Params.String("id")); err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(http.StatusNoContent)
}
