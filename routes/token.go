package routes

import (
	"azugo.io/auth"
	"azugo.io/auth/client"

	"azugo.io/azugo"
)

// token implements POST /token, dispatching on grant_type.
func (h *Handler) token(ctx *azugo.Context) {
	grantType, err := ctx.Form.String("grant_type")
	if err != nil {
		ctx.Error(err)

		return
	}

	switch grantType {
	case client.GrantTypePassword:
		h.passwordGrant(ctx)
	default:
		ctx.Error(auth.NewOAuthErrorFrom(auth.ErrUnsupportedGrantType))
	}
}

// passwordGrant handles the password grant_type.
func (h *Handler) passwordGrant(ctx *azugo.Context) {
	clientID, err := ctx.Form.String("client_id")
	if err != nil {
		ctx.Error(err)

		return
	}

	username, err := ctx.Form.String("username")
	if err != nil {
		ctx.Error(err)

		return
	}

	password, err := ctx.Form.String("password")
	if err != nil {
		ctx.Error(err)

		return
	}

	returnTo := ""
	if v := ctx.Form.StringOptional("return_to"); v != nil {
		returnTo = *v
	}

	res, err := h.auth.Login(ctx, auth.LoginRequest{
		ClientID:   clientID,
		Username:   username,
		Password:   password,
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
