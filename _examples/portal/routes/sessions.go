package routes

import (
	"example/portal/views"

	"azugo.io/auth/session"

	"azugo.io/azugo"
	"azugo.io/templ"
)

// sessionsPage renders the caller's own active sessions, calling the transport-free service
// tier (auth.Auth.ListSessions/IntrospectToken) directly rather than the mounted JSON
// /auth/sessions endpoint - the SSR page is already in-process with *auth.Auth, so it skips
// the self-HTTP round trip.
func (r *router) sessionsPage(ctx *azugo.Context) {
	// IntrospectToken on the presented token resolves the session backing THIS request, so
	// the current row can be flagged - ctx.User() alone only carries the user, not which of
	// their sessions is live right now.
	_, current, err := r.Auth().IntrospectToken(ctx, r.Auth().ReadSessionToken(ctx))
	if err != nil {
		ctx.Error(err)

		return
	}

	sessions, _, err := r.Auth().ListSessions(ctx, current.UserID, &session.Filter{ActiveOnly: true}, nil)
	if err != nil {
		ctx.Error(err)

		return
	}

	items := make([]views.SessionItem, len(sessions))
	for i, s := range sessions {
		items[i] = views.SessionItem{
			ID:        s.ID,
			CreatedAt: s.CreatedAt,
			LastSeen:  s.LastSeen,
			ExpiresAt: s.ExpiresAt,
			Current:   s.ID == current.ID,
		}
	}

	templ.Render(ctx, views.Sessions(items))
}

// revokeSession revokes one of the caller's own sessions and redirects back to the list.
func (r *router) revokeSession(ctx *azugo.Context) {
	if err := r.Auth().RevokeSession(ctx, ctx.User().ID(), ctx.Params.String("id")); err != nil {
		ctx.Error(err)

		return
	}

	ctx.Redirect("/sessions")
}
