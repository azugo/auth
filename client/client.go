// Package client defines the OAuth client model and the Registry that resolves client
// metadata.
package client

import (
	"context"
	"slices"
)

// AuthMethodPassword is the method name for internal username/password login.
const AuthMethodPassword = "password"

// GrantTypeAuthorizationCode is the RFC 6749 grant_type value for the authorization code grant.
const GrantTypeAuthorizationCode = "authorization_code"

// GrantTypePassword is the RFC 6749 grant_type value for the password grant.
const GrantTypePassword = "password"

// AccessTokenType controls which kind of access token is issued to a client.
type AccessTokenType string

const (
	// AccessTokenTypeIntrospect issues an encrypted PASETO v4.local token containing only
	// {sid, jti, iat, exp}, validated via the session store on every request.
	// Default for all clients.
	AccessTokenTypeIntrospect AccessTokenType = "introspect"
	// AccessTokenTypeJWT issues a signed JWT with standard OIDC claims, validated by signature
	// only. Requires a KeyProvider.
	AccessTokenTypeJWT AccessTokenType = "jwt"
)

// TokenEndpointAuthMethod declares how a client authenticates at the token endpoint. Aligns
// with the OIDC token_endpoint_auth_method registration parameter.
type TokenEndpointAuthMethod string

// Registered OIDC token_endpoint_auth_method values.
const (
	TokenEndpointAuthNone         TokenEndpointAuthMethod = "none"          // public client - no secret
	TokenEndpointAuthClientSecret TokenEndpointAuthMethod = "client_secret" // shared secret (PHC-hashed)
	//nolint:gosec
	TokenEndpointAuthPrivateKeyJWT TokenEndpointAuthMethod = "private_key_jwt"
)

// ResponseMode controls the token response shape for a client (SPA vs SSR).
type ResponseMode string

// ResponseMode values.
const (
	ResponseModeJSON     ResponseMode = "json"     // SPA/API: return tokens in JSON body
	ResponseModeRedirect ResponseMode = "redirect" // SSR: Set-Cookie + redirect
	ResponseModeCookie   ResponseMode = "cookie"   // SSR: Set-Cookie only, 204 No Content
)

// MFAPolicy declares whether MFA is required for a client.
type MFAPolicy string

// MFAPolicy values.
const (
	MFAPolicyDisabled MFAPolicy = "disabled" // MFA never required (default)
	MFAPolicyOptional MFAPolicy = "optional" // MFA used if the user is enrolled
	MFAPolicyRequired MFAPolicy = "required" // MFA always required; onboarding if not enrolled
)

// Client is the registered OAuth client metadata.
type Client struct {
	ID            string
	Name          string
	SecretHash    string // PHC-encoded; required when TokenEndpointAuthMethod = client_secret
	PublicKey     string // PEM; required when TokenEndpointAuthMethod = private_key_jwt
	GrantTypes    []string
	Scopes        []string
	RedirectURIs  []string
	Public        bool // true = public client; no client secret required
	AllowNoPrompt bool // true = portal client; silent re-auth allowed
	RequirePKCE   bool // true for public clients
	// RequireDPoP, if true, makes a DPoP proof mandatory at /token; cnf.jkt is bound into
	// issued tokens.
	RequireDPoP             bool
	ResponseMode            ResponseMode
	AccessTokenType         AccessTokenType
	TokenEndpointAuthMethod TokenEndpointAuthMethod // how this client authenticates at /token
	// IDTokenSignedResponseAlg is the OIDC id_token_signed_response_alg registration
	// parameter.
	IDTokenSignedResponseAlg string
	MFAPolicy                MFAPolicy
	// AllowedMFAMethods restricts which registered MFA drivers are offered. Empty = all.
	AllowedMFAMethods []string
	// AllowedAuthMethods restricts which auth methods are permitted. Empty = all.
	// Use AuthMethodPassword for internal login; use the provider name for external ones.
	AllowedAuthMethods []string
	DefaultACR         string // acr applied when the request omits acr_values
	// MinACR that is always forced to at least this level.
	MinACR string
	// AllowedACRValues whitelists the acr values the client may request. Empty = any configured.
	AllowedACRValues []string
	// FederatedLogout, if true, chains GET /logout to the IdP's end_session_endpoint for
	// externally-authenticated sessions if supported.
	FederatedLogout bool
	// PostLogoutRedirectURIs is the exact-match allowlist for post_logout_redirect_uri.
	PostLogoutRedirectURIs []string
}

// AuthMethodAllowed returns true when method is a permitted primary auth method for this
// client.
func (c *Client) AuthMethodAllowed(method string) bool {
	return len(c.AllowedAuthMethods) == 0 || slices.Contains(c.AllowedAuthMethods, method)
}

// GrantTypeAllowed returns true when grantType is one of this client's registered GrantTypes.
func (c *Client) GrantTypeAllowed(grantType string) bool {
	return slices.Contains(c.GrantTypes, grantType)
}

// Registry provides OAuth client metadata.
type Registry interface {
	GetClient(ctx context.Context, clientID string) (*Client, error)
}
