package routes

import (
	"strings"

	"azugo.io/auth/client"

	"azugo.io/azugo"
)

// discoveryDocument is the OIDC discovery document (RFC 8414 / OpenID Connect Discovery 1.0).
type discoveryDocument struct {
	Issuer                                    string   `json:"issuer"`
	AuthorizationEndpoint                     string   `json:"authorization_endpoint"`
	TokenEndpoint                             string   `json:"token_endpoint"`
	UserinfoEndpoint                          string   `json:"userinfo_endpoint"`
	RevocationEndpoint                        string   `json:"revocation_endpoint"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint"`
	JWKSURI                                   string   `json:"jwks_uri,omitempty"`
	ScopesSupported                           []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                    []string `json:"response_types_supported"`
	GrantTypesSupported                       []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
	IDTokenSigningAlgValuesSupported          []string `json:"id_token_signing_alg_values_supported,omitempty"`
	SubjectTypesSupported                     []string `json:"subject_types_supported"`
}

// discovery implements GET /.well-known/openid-configuration.
func (h *Handler) discovery(ctx *azugo.Context) {
	issuer := h.auth.Issuer.URL(ctx.BaseURL(), h.mountPrefix)
	kp := h.auth.Keys()

	ep := h.endpoints

	for _, p := range []*string{&ep.Authorize, &ep.Token, &ep.Userinfo, &ep.JWKS, &ep.Revoke, &ep.Introspect} {
		if *p == "" || strings.Contains(*p, "://") {
			continue
		}

		*p = issuer + *p
	}

	confidentialAuthMethods := []string{"client_secret_basic", "client_secret_post", "private_key_jwt"}

	// client_credentials issues signed JWT access tokens, so it is only available - and only
	// advertised - with a key provider.
	grantTypes := []string{"authorization_code", client.GrantTypePassword}
	if kp != nil {
		grantTypes = []string{"authorization_code", "client_credentials", client.GrantTypePassword}
	}

	doc := discoveryDocument{
		Issuer:                                    issuer,
		AuthorizationEndpoint:                     ep.Authorize,
		TokenEndpoint:                             ep.Token,
		UserinfoEndpoint:                          ep.Userinfo,
		RevocationEndpoint:                        ep.Revoke,
		IntrospectionEndpoint:                     ep.Introspect,
		JWKSURI:                                   ep.JWKS,
		ResponseTypesSupported:                    []string{"code"},
		GrantTypesSupported:                       grantTypes,
		CodeChallengeMethodsSupported:             []string{"S256"},
		TokenEndpointAuthMethodsSupported:         append([]string{string(client.TokenEndpointAuthNone)}, confidentialAuthMethods...),
		IntrospectionEndpointAuthMethodsSupported: confidentialAuthMethods,
		SubjectTypesSupported:                     []string{"public"},
	}

	if kp != nil {
		set, err := kp.KeySet(ctx)
		if err != nil {
			ctx.Error(err)

			return
		}

		doc.ScopesSupported = []string{"openid"}
		doc.IDTokenSigningAlgValuesSupported = set.SigningAlgorithms()
	}

	ctx.JSON(&doc)
}
