package routes

import (
	"azugo.io/auth"
	"azugo.io/auth/token"

	"azugo.io/azugo"
)

// userInfo implements GET /userinfo and returns authenticated user's OIDC UserInfo claims.
func (h *Handler) userInfo(ctx *azugo.Context) {
	info, err := h.auth.UserInfoClaims(ctx, h.auth.ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	// Standard OIDC UserInfo response body over the session's selections.
	body := make(map[string]any, len(info.Context)+5)

	for name, v := range info.Context {
		if !token.ReservedClaim(name) {
			body[name] = v
		}
	}

	body["sub"] = info.ID

	if info.Name != "" {
		body["name"] = info.Name
	}

	if info.ACR != "" {
		body["acr"] = info.ACR
	}

	if email, _ := info.PreferredContact(auth.ChannelEmail); email.Address != "" {
		body["email"] = email.Address
		body["email_verified"] = email.Verified
	}

	if phone, _ := info.PreferredContact(auth.ChannelPhone); phone.Address != "" {
		body["phone_number"] = phone.Address
		body["phone_number_verified"] = phone.Verified
	}

	if len(info.AMR) > 0 {
		body["amr"] = info.AMR
	}

	ctx.JSON(body)
}
