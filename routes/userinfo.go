package routes

import (
	"azugo.io/azugo"
)

// userInfo implements GET /userinfo and returns authenticated user's OIDC UserInfo claims.
func (h *Handler) userInfo(ctx *azugo.Context) {
	info, _, err := h.auth.IntrospectToken(ctx, h.auth.ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	// Standard OIDC UserInfo response body.
	ctx.JSON(&struct {
		Subject string `json:"sub"`
		Name    string `json:"name,omitempty"`
		Email   string `json:"email,omitempty"`
	}{
		Subject: info.ID,
		Name:    info.Name,
		Email:   info.Email,
	})
}
