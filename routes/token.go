package routes

import (
	"encoding/base64"
	"net/url"
	"strings"

	"azugo.io/auth"
	"azugo.io/auth/client"

	"azugo.io/azugo"
	"azugo.io/core/http"
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
	case "authorization_code":
		h.authorizationCodeGrant(ctx)
	case "client_credentials":
		h.clientCredentialsGrant(ctx)
	default:
		ctx.Error(auth.NewOAuthErrorFrom(auth.ErrUnsupportedGrantType))
	}
}

func (h *Handler) tokenEndpointURL(ctx *azugo.Context) string {
	if strings.Contains(h.endpoints.Token, "://") {
		return h.endpoints.Token
	}

	return h.auth.Issuer.URL(ctx.BaseURL(), h.mountPrefix) + h.endpoints.Token
}

// clientCredentials collects the client authentication material from the Authorization
// header (client_secret_basic) or the request body (client_secret_post, private_key_jwt).
func (h *Handler) clientCredentials(ctx *azugo.Context) (auth.ClientCredentials, error) {
	var creds auth.ClientCredentials

	if v := ctx.Form.StringOptional("client_id"); v != nil {
		creds.ClientID = *v
	}

	if v := ctx.Form.StringOptional("client_secret"); v != nil {
		creds.Secret = *v
	}

	if v := ctx.Form.StringOptional("client_assertion_type"); v != nil {
		creds.AssertionType = *v
	}

	if v := ctx.Form.StringOptional("client_assertion"); v != nil {
		creds.Assertion = *v
	}

	basic, ok := strings.CutPrefix(ctx.Header.Get(http.HeaderAuthorization), "Basic ")
	if !ok {
		return creds, nil
	}

	// RFC 6749 §2.3: a request must not use more than one client authentication mechanism.
	if creds.Secret != "" || creds.Assertion != "" {
		return creds, auth.NewOAuthError(http.StatusBadRequest, auth.ErrCodeInvalidRequest, "multiple client authentication mechanisms")
	}

	raw, err := base64.StdEncoding.DecodeString(basic)
	if err != nil {
		return creds, auth.NewOAuthError(http.StatusBadRequest, auth.ErrCodeInvalidRequest, "malformed Basic authorization header")
	}

	id, secret, ok := strings.Cut(string(raw), ":")
	if !ok {
		return creds, auth.NewOAuthError(http.StatusBadRequest, auth.ErrCodeInvalidRequest, "malformed Basic authorization header")
	}

	if id, err = url.QueryUnescape(id); err != nil {
		return creds, auth.NewOAuthError(http.StatusBadRequest, auth.ErrCodeInvalidRequest, "malformed Basic authorization header")
	}

	if secret, err = url.QueryUnescape(secret); err != nil {
		return creds, auth.NewOAuthError(http.StatusBadRequest, auth.ErrCodeInvalidRequest, "malformed Basic authorization header")
	}

	if creds.ClientID != "" && creds.ClientID != id {
		return creds, auth.NewOAuthError(http.StatusBadRequest, auth.ErrCodeInvalidRequest, "client_id does not match Basic authorization header")
	}

	creds.ClientID = id
	creds.Secret = secret

	return creds, nil
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
		IP:         ctx.IP().String(),
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	h.writeLoginResult(ctx, res)
}

// authorizationCodeGrant handles the authorization_code grant_type.
func (h *Handler) authorizationCodeGrant(ctx *azugo.Context) {
	codeVal, err := ctx.Form.String("code")
	if err != nil {
		ctx.Error(err)

		return
	}

	creds, err := h.clientCredentials(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	req := auth.AuthorizationCodeGrantRequest{
		Credentials:   creds,
		Code:          codeVal,
		BaseURL:       ctx.BaseURL(),
		MountPath:     h.mountPrefix,
		TokenEndpoint: h.tokenEndpointURL(ctx),
		IP:            ctx.IP().String(),
	}

	if v := ctx.Form.StringOptional("redirect_uri"); v != nil {
		req.RedirectURI = *v
	}

	if v := ctx.Form.StringOptional("code_verifier"); v != nil {
		req.CodeVerifier = *v
	}

	res, err := h.auth.AuthorizationCodeGrant(ctx, req)
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.JSON(&res)
}

// clientCredentialsGrant handles the client_credentials grant_type.
func (h *Handler) clientCredentialsGrant(ctx *azugo.Context) {
	creds, err := h.clientCredentials(ctx)
	if err != nil {
		ctx.Error(err)

		return
	}

	scope := ""
	if v := ctx.Form.StringOptional("scope"); v != nil {
		scope = *v
	}

	res, err := h.auth.ClientCredentialsGrant(ctx, auth.ClientCredentialsGrantRequest{
		Credentials:   creds,
		Scope:         scope,
		BaseURL:       ctx.BaseURL(),
		MountPath:     h.mountPrefix,
		TokenEndpoint: h.tokenEndpointURL(ctx),
		IP:            ctx.IP().String(),
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.JSON(&res)
}
