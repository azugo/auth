// Package routes is the optional HTTP adapter tier over the transport-free auth service.
package routes

import (
	"cmp"

	"azugo.io/auth"
	"azugo.io/auth/session"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// tokenTypeBearer is the RFC 6750 token_type value.
const tokenTypeBearer = "Bearer"

// OIDCRoutes holds the always-mounted protocol adapters.
type OIDCRoutes struct {
	Authorize     azugo.RequestHandler // POST /authorize (portal silent re-auth)
	AuthorizeCode azugo.RequestHandler // GET /authorize (authorization-code flow)
	Token         azugo.RequestHandler // POST /token (password, authorization_code, client_credentials)
	Revoke        azugo.RequestHandler // POST /revoke (RFC 7009)
	Introspect    azugo.RequestHandler // POST /introspect (RFC 7662)
	Discovery     azugo.RequestHandler // GET /.well-known/openid-configuration
	UserInfo      azugo.RequestHandler // GET /userinfo
	JWKS          azugo.RequestHandler // GET /.well-known/jwks.json
	Logout        azugo.RequestHandler // GET /logout (RP-initiated browser logout)
}

// ExternalRoutes holds the external-provider adapters: the browser redirects are always
// mounted ({provider} resolves per request, 404 on unknown); the linking adapters are set only
// when an IdentityStore is configured and mounted under LinkingGroup.
type ExternalRoutes struct {
	Login          azugo.RequestHandler // GET /external/{provider}/login
	Callback       azugo.RequestHandler // GET /external/{provider}/callback
	LogoutCallback azugo.RequestHandler // GET /external/{provider}/logout/callback
	Link           azugo.RequestHandler // GET /external/{provider}/link
	Identities     azugo.RequestHandler // GET /external/identities
	Unlink         azugo.RequestHandler // DELETE /external/{provider}/identities/{id}
}

// SessionRoutes holds the suppressible self-service session adapters.
type SessionRoutes struct {
	Get    azugo.RequestHandler // GET /session
	Delete azugo.RequestHandler // DELETE /session
	List   azugo.RequestHandler // GET /sessions
	Revoke azugo.RequestHandler // DELETE /sessions/{id}
}

// MFARoutes holds the MFA adapters, set only when an MFA store is configured and mounted under
// MFAGroup.
type MFARoutes struct {
	Verify       azugo.RequestHandler // POST /mfa/verify
	Begin        azugo.RequestHandler // POST /mfa/begin
	Resend       azugo.RequestHandler // POST /mfa/resend
	Status       azugo.RequestHandler // GET /mfa/status
	Callback     azugo.RequestHandler // POST /mfa/{method}/callback
	Methods      azugo.RequestHandler // GET /mfa/methods
	Enroll       azugo.RequestHandler // POST /mfa/enroll/{method}
	EnrollFinish azugo.RequestHandler // POST /mfa/enroll/{method}/finish
	EnrollRevoke azugo.RequestHandler // DELETE /mfa/enroll/{method}
	// EnrollmentRevoke removes one enrollment.
	EnrollmentRevoke azugo.RequestHandler // DELETE /mfa/enroll/{method}/{id}
}

// Handler exposes the HTTP adapters over a constructed *auth.Auth as grouped fields.
type Handler struct {
	OIDC     OIDCRoutes
	External ExternalRoutes
	Session  SessionRoutes
	MFA      MFARoutes

	auth *auth.Auth
	// mountPrefix is the prefix Bind mounted this Handler under.
	mountPrefix string
	// logoutConfirmation renders the page asking the user to confirm a logout.
	logoutConfirmation azugo.RequestHandler
	// endpoints holds the path or absolute URL discovery reports for each endpoint - the
	// default mountPrefix-relative path, or an Option override applied in New.
	endpoints discoveryEndpoints
}

// discoveryEndpoints holds the path (or absolute URL) reported for each discovery endpoint.
type discoveryEndpoints struct {
	Authorize  string
	Token      string
	Userinfo   string
	JWKS       string
	Revoke     string
	Introspect string
	EndSession string
}

// Group identifies a suppressible endpoint group for Bind.
type Group int

const (
	// SessionGroup mounts /sessions and /session routes.
	SessionGroup Group = iota
	// LinkingGroup mounts the account-linking routes (/external/{provider}/link and
	// /external/identities), distinct from the always-on external login redirects.
	LinkingGroup
	// MFAGroup mounts the /mfa/* routes.
	MFAGroup
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

	mountPrefix        *string
	logoutConfirmation azugo.RequestHandler
	authorizeEndpoint  string
	tokenEndpoint      string
	userinfoEndpoint   string
	jwksEndpoint       string
	revokeEndpoint     string
	introspectEndpoint string
	endSessionEndpoint string
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

// AuthorizeEndpoint overrides the authorization_endpoint URL reported by the discovery
// document.
type AuthorizeEndpoint string

func (o AuthorizeEndpoint) apply(b *bindOptions) {
	b.authorizeEndpoint = string(o)
}

// RevokeEndpoint overrides the revocation_endpoint URL reported by the discovery document.
type RevokeEndpoint string

func (o RevokeEndpoint) apply(b *bindOptions) {
	b.revokeEndpoint = string(o)
}

// IntrospectEndpoint overrides the introspection_endpoint URL reported by the discovery
// document.
type IntrospectEndpoint string

func (o IntrospectEndpoint) apply(b *bindOptions) {
	b.introspectEndpoint = string(o)
}

// LogoutConfirmation supplies the page rendered under Configuration.LogoutPolicy "confirm" when
// a logout arrives without an id_token_hint. The page must post back to the same path.
func LogoutConfirmation(h azugo.RequestHandler) Option {
	return logoutConfirmationOption{h: h}
}

type logoutConfirmationOption struct {
	h azugo.RequestHandler
}

func (o logoutConfirmationOption) apply(b *bindOptions) {
	b.logoutConfirmation = o.h
}

// EndSessionEndpoint overrides the end_session_endpoint URL reported by the discovery
// document.
type EndSessionEndpoint string

func (o EndSessionEndpoint) apply(b *bindOptions) {
	b.endSessionEndpoint = string(o)
}

// supportedGroups calculates supported groups to mount based on implemented stores.
func supportedGroups(a *auth.Auth) []Group {
	groups := []Group{SessionGroup}

	if a.Identities() != nil {
		groups = append(groups, LinkingGroup)
	}

	if a.MFA() != nil {
		groups = append(groups, MFAGroup)
	}

	return groups
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
			Authorize:  cmp.Or(o.authorizeEndpoint, "/authorize"),
			Token:      cmp.Or(o.tokenEndpoint, "/token"),
			Userinfo:   cmp.Or(o.userinfoEndpoint, "/userinfo"),
			JWKS:       cmp.Or(o.jwksEndpoint, "/.well-known/jwks.json"),
			Revoke:     cmp.Or(o.revokeEndpoint, "/revoke"),
			Introspect: cmp.Or(o.introspectEndpoint, "/introspect"),
			EndSession: cmp.Or(o.endSessionEndpoint, "/logout"),
		},
	}

	if o.mountPrefix != nil {
		h.mountPrefix = *o.mountPrefix
	}

	h.logoutConfirmation = o.logoutConfirmation

	h.OIDC.Authorize = h.authorize
	h.OIDC.AuthorizeCode = h.authorizeCode
	h.OIDC.Token = h.token
	h.OIDC.Revoke = h.revoke
	h.OIDC.Introspect = h.introspect
	h.OIDC.Discovery = h.discovery
	h.OIDC.UserInfo = h.userInfo
	h.OIDC.Logout = h.logout

	h.External.Login = h.externalLogin
	h.External.Callback = h.externalCallback
	h.External.LogoutCallback = h.externalLogoutCallback

	if a.Identities() != nil {
		h.External.Link = h.externalLink
		h.External.Identities = h.listIdentities
		h.External.Unlink = h.unlinkIdentity
	}

	// Bind mounts the route and discovery advertises
	// the endpoint based on what is set here.
	if a.Keys() != nil {
		h.OIDC.JWKS = h.jwks
	} else {
		h.endpoints.JWKS = ""
	}

	if a.MFA() != nil {
		h.MFA.Verify = h.mfaVerify
		h.MFA.Begin = h.mfaBegin
		h.MFA.Resend = h.mfaResend
		h.MFA.Status = h.mfaStatus
		h.MFA.Callback = h.mfaCallback
		h.MFA.Methods = h.mfaMethods
		h.MFA.Enroll = h.mfaEnroll
		h.MFA.EnrollFinish = h.mfaEnrollFinish
		h.MFA.EnrollRevoke = h.mfaEnrollRevoke
		h.MFA.EnrollmentRevoke = h.mfaEnrollmentRevoke
	}

	h.Session.Get = h.getSession
	h.Session.Delete = h.deleteSession

	if _, ok := a.Sessions().(session.Lister); ok {
		h.Session.List = h.listSessions
		h.Session.Revoke = h.revokeSession
	}

	return h
}

// SecurityHeaders is a middleware that marks responses as non-cacheable (RFC 6749 §5.1) and
// disables content-type sniffing.
func SecurityHeaders(next azugo.RequestHandler) azugo.RequestHandler {
	return func(ctx *azugo.Context) {
		ctx.Header.Set(http.HeaderCacheControl, "no-store")
		ctx.Header.Set(http.HeaderPragma, "no-cache")
		ctx.Header.Set(http.HeaderXContentTypeOptions, "nosniff")

		next(ctx)
	}
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

	g.Get("/.well-known/openid-configuration", h.OIDC.Discovery)

	if h.OIDC.JWKS != nil {
		g.Get("/.well-known/jwks.json", h.OIDC.JWKS)
	}

	g.Use(SecurityHeaders)

	g.Get("/authorize", h.OIDC.AuthorizeCode)
	g.Post("/authorize", h.OIDC.Authorize)
	g.Post("/token", h.OIDC.Token)
	g.Post("/revoke", h.OIDC.Revoke)
	g.Post("/introspect", h.OIDC.Introspect)
	g.Get("/userinfo", h.OIDC.UserInfo)
	g.Get("/logout", h.OIDC.Logout)
	g.Post("/logout", h.OIDC.Logout)

	g.Get("/external/{provider}/login", h.External.Login)
	g.Get("/external/{provider}/callback", h.External.Callback)
	g.Get("/external/{provider}/logout/callback", h.External.LogoutCallback)

	for _, group := range groups {
		switch group {
		case SessionGroup:
			g.Get("/session", h.Session.Get)
			g.Delete("/session", h.Session.Delete)

			if h.Session.List != nil {
				g.Get("/sessions", h.Session.List)
			}

			if h.Session.Revoke != nil {
				g.Delete("/sessions/{id}", h.Session.Revoke)
			}
		case LinkingGroup:
			if h.External.Link == nil {
				continue
			}

			g.Get("/external/{provider}/link", h.External.Link)
			g.Get("/external/identities", h.External.Identities)
			g.Delete("/external/{provider}/identities/{id}", h.External.Unlink)
		case MFAGroup:
			if h.MFA.Verify == nil {
				continue
			}

			g.Post("/mfa/verify", h.MFA.Verify)
			g.Post("/mfa/begin", h.MFA.Begin)
			g.Post("/mfa/resend", h.MFA.Resend)
			g.Get("/mfa/status", h.MFA.Status)
			g.Get("/mfa/methods", h.MFA.Methods)
			g.Post("/mfa/enroll/{method}", h.MFA.Enroll)
			g.Post("/mfa/enroll/{method}/finish", h.MFA.EnrollFinish)
			g.Delete("/mfa/enroll/{method}", h.MFA.EnrollRevoke)
			g.Delete("/mfa/enroll/{method}/{id}", h.MFA.EnrollmentRevoke)
			g.Post("/mfa/{method}/callback", h.MFA.Callback)
		}
	}

	return h
}

// writeLoginResult applies a LoginResult's cookie directive and writes the response shape
// implied by client.ResponseMode.
func (h *Handler) writeLoginResult(ctx *azugo.Context, res auth.LoginResult) {
	h.auth.WriteCookie(ctx, res.Cookie)

	if res.Status != session.StatusActive {
		if res.ReturnTo != "" {
			ctx.Redirect(res.ReturnTo)

			return
		}

		ctx.StatusCode(http.StatusAccepted)
		ctx.JSON(&struct {
			Status      session.Status `json:"status"`
			StepToken   string         `json:"step_token,omitempty"`
			Available   []string       `json:"available,omitempty"`
			Selected    string         `json:"selected,omitempty"`
			Interaction string         `json:"interaction,omitempty"`
			Data        map[string]any `json:"data,omitempty"`
		}{
			Status:      res.Status,
			StepToken:   res.StepToken,
			Available:   res.Available,
			Selected:    res.Selected,
			Interaction: res.Interaction,
			Data:        res.Data,
		})

		return
	}

	switch {
	case res.AccessToken != "":
		// RFC 6749 §5.1 access token response body.
		ctx.JSON(&struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			IDToken     string `json:"id_token,omitempty"`
		}{AccessToken: res.AccessToken, TokenType: tokenTypeBearer, ExpiresIn: res.ExpiresIn, IDToken: res.IDToken})
	case res.ReturnTo != "":
		ctx.Redirect(res.ReturnTo)
	default:
		ctx.StatusCode(http.StatusNoContent)
	}
}
