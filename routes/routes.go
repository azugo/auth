// Package routes is the optional HTTP adapter tier over the transport-free auth service.
package routes

import (
	"azugo.io/auth"
	"azugo.io/auth/session"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// OIDCRoutes holds the always-mounted protocol adapters.
type OIDCRoutes struct {
	Authorize azugo.RequestHandler // POST /authorize (portal silent re-auth)
	Token     azugo.RequestHandler // POST /token (password grant)
}

// SessionRoutes holds the suppressible self-service session adapters.
type SessionRoutes struct {
	Get    azugo.RequestHandler // GET /session
	Delete azugo.RequestHandler // DELETE /session
	List   azugo.RequestHandler // GET /sessions
	Revoke azugo.RequestHandler // DELETE /sessions/{id}
}

// Handler exposes the HTTP adapters over a constructed *auth.Auth as grouped fields.
type Handler struct {
	OIDC    OIDCRoutes
	Session SessionRoutes

	auth *auth.Auth
}

// Group identifies a suppressible endpoint group for Bind.
type Group int

const (
	// SessionGroup mounts /sessions and /session routes.
	SessionGroup Group = iota
)

func (g Group) apply(o *bindOptions) {
	o.groupsSet = true
	o.groups = append(o.groups, g)
}

// Option to configure Bind.
type Option interface {
	apply(o *bindOptions)
}

type bindOptions struct {
	groups    []Group
	groupsSet bool
}

// OIDC explicitly forces Bind to mount only OIDC routes.
func OIDC() Option {
	return oidcOption{}
}

type oidcOption struct{}

func (oidcOption) apply(o *bindOptions) {
	o.groupsSet = true
}

// supportedGroups calculates supported groups to mount based on implemented stores.
func supportedGroups(_ *auth.Auth) []Group {
	return []Group{SessionGroup}
}

// New builds the grouped HTTP adapters.
func New(a *auth.Auth) *Handler {
	h := &Handler{auth: a}

	h.OIDC.Authorize = h.authorize
	h.OIDC.Token = h.token

	h.Session.Get = h.getSession
	h.Session.Delete = h.deleteSession

	if _, ok := a.Sessions().(session.Lister); ok {
		h.Session.List = h.listSessions
		h.Session.Revoke = h.revokeSession
	}

	return h
}

// Bind mounts routes under prefix on router.
func Bind(r azugo.Router, prefix string, a *auth.Auth, opts ...Option) *Handler {
	var o bindOptions
	for _, opt := range opts {
		opt.apply(&o)
	}

	groups := o.groups
	if !o.groupsSet {
		groups = supportedGroups(a)
	}

	h := New(a)
	g := r.Group(prefix)

	g.Post("/authorize", h.OIDC.Authorize)
	g.Post("/token", h.OIDC.Token)

	for _, group := range groups {
		if group == SessionGroup {
			g.Get("/session", h.Session.Get)
			g.Delete("/session", h.Session.Delete)

			if h.Session.List != nil {
				g.Get("/sessions", h.Session.List)
			}

			if h.Session.Revoke != nil {
				g.Delete("/sessions/{id}", h.Session.Revoke)
			}
		}
	}

	return h
}

// writeLoginResult applies a LoginResult's cookie directive and writes the response shape
// implied by client.ResponseMode.
func (h *Handler) writeLoginResult(ctx *azugo.Context, res auth.LoginResult) {
	h.auth.WriteCookie(ctx, res.Cookie)

	switch {
	case res.AccessToken != "":
		// RFC 6749 §5.1 access token response body.
		ctx.JSON(&struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
		}{AccessToken: res.AccessToken, TokenType: "Bearer", ExpiresIn: res.ExpiresIn})
	case res.Redirect != "":
		ctx.Redirect(res.Redirect)
	default:
		ctx.StatusCode(http.StatusNoContent)
	}
}
