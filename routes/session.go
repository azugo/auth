package routes

import (
	"time"

	"azugo.io/auth"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// sessionLifetime is the session state answered by GET /session and POST /session/activity.
type sessionLifetime struct {
	ExpiresAt     time.Time `json:"expires_at"`
	IdleExpiresAt time.Time `json:"idle_expires_at,omitzero"`
}

// getSession implements GET /session: the presented token's session lifetime, without counting
// as activity.
func (h *Handler) getSession(ctx *azugo.Context) {
	_, sess, err := h.auth.IntrospectToken(ctx, h.auth.ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.JSON(sessionLifetime{ExpiresAt: sess.ExpiresAt, IdleExpiresAt: sess.IdleExpiresAt})
}

// sessionActivity implements POST /session/activity: records user activity, such as input the
// SPA handles without calling the backend, and answers the session lifetime.
func (h *Handler) sessionActivity(ctx *azugo.Context) {
	sess, err := h.auth.KeepAlive(ctx, h.auth.ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.JSON(sessionLifetime{ExpiresAt: sess.ExpiresAt, IdleExpiresAt: sess.IdleExpiresAt})
}

// deleteSession implements DELETE /session: the authoritative, non-redirecting logout for
// SPA/API clients.
func (h *Handler) deleteSession(ctx *azugo.Context) {
	res, err := h.auth.Logout(ctx, auth.LogoutRequest{
		Token:     h.auth.ReadSessionToken(ctx),
		BasePath:  ctx.BasePath(),
		MountPath: h.mountPrefix,
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	h.auth.WriteCookie(ctx, res.ClearCookie)
	ctx.StatusCode(http.StatusNoContent)
}
