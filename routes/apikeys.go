package routes

import (
	"time"

	"azugo.io/auth"
	"azugo.io/auth/apikey"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// apiKeyOutput is the JSON shape of an API key; Token is set only at creation and rotation.
type apiKeyOutput struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Scope     string     `json:"scope"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
	Token     string     `json:"token,omitempty"`
}

func newAPIKeyOutput(k *apikey.Key) apiKeyOutput {
	return apiKeyOutput{
		ID:        k.ID,
		Name:      k.Name,
		Scope:     k.Scope,
		CreatedAt: k.CreatedAt,
		ExpiresAt: k.ExpiresAt,
		RevokedAt: k.RevokedAt,
		RotatedAt: k.RotatedAt,
	}
}

// listAPIKeys implements GET /apikeys: the caller's own keys, metadata only.
func (h *Handler) listAPIKeys(ctx *azugo.Context) {
	keys, pages, err := h.auth.ListAPIKeys(ctx, h.auth.ReadSessionToken(ctx), nil, ctx.Paging())
	if err != nil {
		ctx.Error(err)

		return
	}

	out := make([]apiKeyOutput, len(keys))
	for i, k := range keys {
		out[i] = newAPIKeyOutput(k)
	}

	ctx.SetPaging(map[string]string{"type": "apikeys"}, pages)
	ctx.JSON(out)
}

// createAPIKey implements POST /apikeys: create a key, answering its token once.
func (h *Handler) createAPIKey(ctx *azugo.Context) {
	var in struct {
		Name      string     `json:"name"`
		Scope     string     `json:"scope"`
		ExpiresAt *time.Time `json:"expires_at"`
	}

	if err := ctx.Body.JSON(&in); err != nil {
		ctx.Error(err)

		return
	}

	res, err := h.auth.CreateAPIKey(ctx, auth.CreateAPIKeyRequest{
		Token:     h.auth.ReadSessionToken(ctx),
		Name:      in.Name,
		Scope:     in.Scope,
		ExpiresAt: in.ExpiresAt,
		IP:        ctx.IP().String(),
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	out := newAPIKeyOutput(res.Key)
	out.Token = res.Token

	ctx.StatusCode(http.StatusCreated)
	ctx.JSON(out)
}

// rotateAPIKey implements POST /apikeys/{id}/rotate: replace a key's token, answering the new
// one once.
func (h *Handler) rotateAPIKey(ctx *azugo.Context) {
	res, err := h.auth.RotateAPIKey(ctx, auth.APIKeyRequest{
		Token: h.auth.ReadSessionToken(ctx),
		ID:    ctx.Params.String("id"),
		IP:    ctx.IP().String(),
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	out := newAPIKeyOutput(res.Key)
	out.Token = res.Token

	ctx.JSON(out)
}

// revokeAPIKey implements DELETE /apikeys/{id}: revoke one of the caller's own keys.
func (h *Handler) revokeAPIKey(ctx *azugo.Context) {
	if err := h.auth.RevokeAPIKey(ctx, auth.APIKeyRequest{
		Token: h.auth.ReadSessionToken(ctx),
		ID:    ctx.Params.String("id"),
		IP:    ctx.IP().String(),
	}); err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(http.StatusNoContent)
}
