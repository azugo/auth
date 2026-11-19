package routes

import (
	"time"

	"azugo.io/auth"
	"azugo.io/auth/session"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// sessionState is the session state answered by GET /session and POST /session/activity.
type sessionState struct {
	Status        session.Status `json:"status"`
	Step          string         `json:"step,omitempty"`
	ExpiresAt     time.Time      `json:"expires_at"`
	IdleExpiresAt time.Time      `json:"idle_expires_at,omitzero"`
}

// getSession implements GET /session: the presented token's session state, a pending one included
// (e.g. pending_password_change, for an SPA resuming the flow), without counting as activity.
func (h *Handler) getSession(ctx *azugo.Context) {
	sess, err := h.auth.PendingSession(ctx, h.auth.ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.JSON(sessionState{
		Status:        sess.Status,
		Step:          sess.Step,
		ExpiresAt:     sess.ExpiresAt,
		IdleExpiresAt: sess.IdleExpiresAt,
	})
}

// sessionActivity implements POST /session/activity: records user activity, such as input the
// SPA handles without calling the backend, and answers the session lifetime.
func (h *Handler) sessionActivity(ctx *azugo.Context) {
	sess, err := h.auth.KeepAlive(ctx, h.auth.ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.JSON(sessionState{
		Status:        sess.Status,
		Step:          sess.Step,
		ExpiresAt:     sess.ExpiresAt,
		IdleExpiresAt: sess.IdleExpiresAt,
	})
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
