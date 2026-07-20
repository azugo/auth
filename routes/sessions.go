package routes

import (
	"time"

	"azugo.io/auth/session"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

ype sessionResponse struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	ExpiresAt time.Time `json:"expires_at"`
	Current   bool      `json:"current"`
}

// listSessions implements GET /sessions: the caller's own active sessions, current-flagged.
func (h *Handler) listSessions(ctx *azugo.Context) {
	info, sess, err := h.auth.IntrospectToken(ctx, h.auth.ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	sessions, pages, err := h.auth.ListSessions(ctx, info.ID, &session.Filter{ActiveOnly: true}, ctx.Paging())
	if err != nil {
		ctx.Error(err)

		return
	}

	out := make([]sessionResponse, len(sessions))
	for i, s := range sessions {
		out[i] = sessionResponse{
			ID:        s.ID,
			ClientID:  s.ClientID,
			CreatedAt: s.CreatedAt,
			LastSeen:  s.LastSeen,
			ExpiresAt: s.ExpiresAt,
			Current:   s.ID == sess.ID,
		}
	}

	ctx.SetPaging(map[string]string{"type": "sessions"}, pages)
	ctx.JSON(out)
}

// revokeSession implements DELETE /sessions/{id}: caller-filtered revoke of one of the
// caller's own sessions.
func (h *Handler) revokeSession(ctx *azugo.Context) {
	info, _, err := h.auth.IntrospectToken(ctx, h.auth.ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	if err := h.auth.RevokeSession(ctx, info.ID, ctx.Params.String("id")); err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(http.StatusNoContent)
}
