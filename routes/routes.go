// Package routes is the optional HTTP adapter tier over the transport-free auth service.
package routes

import (
	"cmp"

	"azugo.io/auth"
	"azugo.io/auth/session"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// OIDCRoutes holds the always-mounted protocol adapters.
type OIDCRoutes struct {
	Authorize azugo.RequestHandler // POST /authorize (portal silent re-auth)
	Token     azugo.RequestHandler // POST /token (password grant)
	Discovery azugo.RequestHandler // GET /.well-known/openid-configuration
	UserInfo  azugo.RequestHandler // GET /userinfo
	JWKS      azugo.RequestHandler // GET /.well-known/jwks.json
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
	// mountPrefix is the prefix Bind mounted this Handler under.
	mountPrefix string
	// endpoints holds the path or absolute URL discovery reports for each endpoint - the
	// default mountPrefix-relative path, or an Option override applied in New.
	endpoints discoveryEndpoints
}

// discoveryEndpoints holds the path (or absolute URL) reported for each discovery endpoint.
type discoveryEndpoints struct {
	Token    string
	Userinfo string
	JWKS     string
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

	mountPrefix      *string
	tokenEndpoint    string
	userinfoEndpoint string
	jwksEndpoint     string
}

// OIDC explicitly forces Bind to mount only OIDC routes.
func OIDC() Option {
	return oidcOption{}
}

type oidcOption struct{}

func (oidcOption) apply(o *bindOptions) {
	o.groupsSet = true
}

// MountPrefix sets the prefix used to derive the issuer and default endpoint URLs.
type MountPrefix string

func (o MountPrefix) apply(b *bindOptions) {
	p := string(o)
	b.mountPrefix = &p
}

// TokenEndpoint overrides the token_endpoint URL reported by the discovery document.
type TokenEndpoint string

func (o TokenEndpoint) apply(b *bindOptions) {
	b.tokenEndpoint = string(o)
}

// UserinfoEndpoint overrides the userinfo_endpoint URL reported by the discovery document.
type UserinfoEndpoint string

func (o UserinfoEndpoint) apply(b *bindOptions) {
	b.userinfoEndpoint = string(o)
}

// JWKSEndpoint overrides the jwks_uri URL reported by the discovery document.
type JWKSEndpoint string

func (o JWKSEndpoint) apply(b *bindOptions) {
	b.jwksEndpoint = string(o)
}

// supportedGroups calculates supported groups to mount based on implemented stores.
func supportedGroups(_ *auth.Auth) []Group {
	return []Group{SessionGroup}
}

// New builds the grouped HTTP adapters.
func New(a *auth.Auth, opts ...Option) *Handler {
	var o bindOptions
	for _, opt := range opts {
		opt.apply(&o)
	}

	h := &Handler{
		auth: a,
		endpoints: discoveryEndpoints{
			Token:    cmp.Or(o.tokenEndpoint, "/token"),
			Userinfo: cmp.Or(o.userinfoEndpoint, "/userinfo"),
			JWKS:     cmp.Or(o.jwksEndpoint, "/.well-known/jwks.json"),
		},
	}

	if o.mountPrefix != nil {
		h.mountPrefix = *o.mountPrefix
	}

	h.OIDC.Authorize = h.authorize
	h.OIDC.Token = h.token
	h.OIDC.Discovery = h.discovery
	h.OIDC.UserInfo = h.userInfo

	if a.Keys() != nil {
		h.OIDC.JWKS = h.jwks
	}

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

	h := New(a, opts...)
	h.mountPrefix = prefix
	g := r.Group(prefix)

	g.Post("/authorize", h.OIDC.Authorize)
	g.Post("/token", h.OIDC.Token)
	g.Get("/.well-known/openid-configuration", h.OIDC.Discovery)
	g.Get("/userinfo", h.OIDC.UserInfo)

	if h.OIDC.JWKS != nil {
		g.Get("/.well-known/jwks.json", h.OIDC.JWKS)
	}

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
			IDToken     string `json:"id_token,omitempty"`
		}{AccessToken: res.AccessToken, TokenType: "Bearer", ExpiresIn: res.ExpiresIn, IDToken: res.IDToken})
	case res.Redirect != "":
		ctx.Redirect(res.Redirect)
	default:
		ctx.StatusCode(http.StatusNoContent)
	}
}
