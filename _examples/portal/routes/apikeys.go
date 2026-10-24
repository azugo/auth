package routes

import (
	"strconv"
	"strings"
	"time"

	"example/portal/views"

	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/templ"
)

// apiKeysPage lists the caller's API keys and offers to create one limited to a subset of the
// caller's own scope.
func (r *router) apiKeysPage(ctx *azugo.Context) {
	tok := r.Auth().ReadSessionToken(ctx)

	info, _, err := r.Auth().IntrospectToken(ctx, tok)
	if err != nil {
		ctx.Error(err)

		return
	}

	keys, _, err := r.Auth().ListAPIKeys(ctx, tok, nil, nil)
	if err != nil {
		ctx.Error(err)

		return
	}

	var created *views.NewAPIKey

	var k views.NewAPIKey
	if ok, _ := ctx.Flash.Get("apikey", &k); ok {
		created = &k
	}

	message := ""
	if errs := ctx.Flash.Errors(); len(errs) > 0 {
		message = errs[0]
	}

	templ.Render(ctx, views.APIKeys(strings.Fields(info.Scope), keys, created, message))
}

// createAPIKey submits the new key form and shows the token once.
func (r *router) createAPIKey(ctx *azugo.Context) {
	req := auth.CreateAPIKeyRequest{
		Token: r.Auth().ReadSessionToken(ctx),
		Scope: strings.Join(ctx.Form.Values("scope"), " "),
		IP:    ctx.IP().String(),
	}

	if v := ctx.Form.StringOptional("name"); v != nil {
		req.Name = *v
	}

	if v := ctx.Form.StringOptional("expires"); v != nil && *v != "" {
		days, err := strconv.Atoi(*v)
		if err != nil || days <= 0 {
			ctx.Flash.Error("Choose a valid expiry.")
			ctx.Redirect("/apikeys")

			return
		}

		at := time.Now().AddDate(0, 0, days)
		req.ExpiresAt = &at
	}

	res, err := r.Auth().CreateAPIKey(ctx, req)
	if err != nil {
		if r.fatal(ctx, err, "/apikeys") {
			return
		}

		ctx.Flash.Error(errorMessage(err, "Could not create the key."))
		ctx.Redirect("/apikeys")

		return
	}

	_ = ctx.Flash.Set("apikey", views.NewAPIKey{Name: res.Key.Name, Token: res.Token})
	ctx.Redirect("/apikeys")
}

// rotateAPIKey replaces the token of one of the caller's keys and shows the new one once.
func (r *router) rotateAPIKey(ctx *azugo.Context) {
	res, err := r.Auth().RotateAPIKey(ctx, auth.APIKeyRequest{
		Token: r.Auth().ReadSessionToken(ctx),
		ID:    ctx.Params.String("id"),
		IP:    ctx.IP().String(),
	})
	if err != nil {
		if r.fatal(ctx, err, "/apikeys") {
			return
		}

		ctx.Flash.Error(errorMessage(err, "Could not rotate the key."))
		ctx.Redirect("/apikeys")

		return
	}

	_ = ctx.Flash.Set("apikey", views.NewAPIKey{Name: res.Key.Name, Token: res.Token})
	ctx.Redirect("/apikeys")
}

// revokeAPIKey revokes one of the caller's keys.
func (r *router) revokeAPIKey(ctx *azugo.Context) {
	err := r.Auth().RevokeAPIKey(ctx, auth.APIKeyRequest{
		Token: r.Auth().ReadSessionToken(ctx),
		ID:    ctx.Params.String("id"),
		IP:    ctx.IP().String(),
	})
	if err != nil {
		if r.fatal(ctx, err, "/apikeys") {
			return
		}

		ctx.Flash.Error(errorMessage(err, "Could not revoke the key."))
	}

	ctx.Redirect("/apikeys")
}

// me implements GET /api/me, a JSON endpoint an API key can call: who the caller is and the
// scope the credential carries.
func (r *router) me(ctx *azugo.Context) {
	info, err := r.Auth().IntrospectWithAPIKey(ctx, r.Auth().ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.JSON(map[string]string{"id": info.ID, "name": info.Name, "scope": info.Scope})
}
