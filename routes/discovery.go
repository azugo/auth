package routes

import (
	"strings"

	"azugo.io/auth/client"

	"azugo.io/azugo"
)

// discoveryDocument is the OIDC discovery document (RFC 8414 / OpenID Connect Discovery 1.0).
type discoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
}

// discovery implements GET /.well-known/openid-configuration.
func (h *Handler) discovery(ctx *azugo.Context) {
	issuer := h.auth.Issuer.URL(ctx.BaseURL(), h.mountPrefix)

	// resolve endpoint paths
	ep := h.endpoints
	for _, p := range []*string{&ep.Token, &ep.Userinfo, &ep.JWKS} {
		if !strings.Contains(*p, "://") {
			*p = issuer + *p
		}
	}

	doc := discoveryDocument{
		Issuer:                            issuer,
		TokenEndpoint:                     ep.Token,
		UserinfoEndpoint:                  ep.Userinfo,
		GrantTypesSupported:               []string{client.GrantTypePassword},
		TokenEndpointAuthMethodsSupported: []string{string(client.TokenEndpointAuthNone)},
		SubjectTypesSupported:             []string{"public"},
	}

	if kp := h.auth.Keys(); kp != nil {
		set, err := kp.KeySet(ctx)
		if err != nil {
			ctx.Error(err)

			return
		}

		doc.JWKSURI = ep.JWKS
		doc.ScopesSupported = []string{"openid"}
		doc.IDTokenSigningAlgValuesSupported = set.SigningAlgorithms()
	}

	ctx.JSON(&doc)
}
