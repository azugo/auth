// Package oidc implements a generic OpenID Connect authorization-code provider used as the
// shared core of the concrete IdP drivers.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"azugo.io/auth/provider"

	"azugo.io/core/http"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
)

var signingAlgorithms = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

// Config configures a generic OIDC provider.
type Config struct {
	// Issuer is the expected id_token iss value and the discovery document base URL.
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// Scopes defaults to "openid profile email"; "openid" is always included.
	Scopes []string
	// AuthorizationEndpoint, TokenEndpoint, JWKSURI and EndSessionEndpoint override the
	// discovered values (all empty = discover from Issuer).
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	EndSessionEndpoint    string
	// AuthParams are extra authorization request parameters (prompt, hd, ...).
	AuthParams url.Values
	// IssuerCheck overrides the exact iss equality check (multi-tenant IdPs).
	IssuerCheck func(iss string) error
	// ClockSkew is the leeway allowed on id_token time claims; zero validates strictly.
	ClockSkew time.Duration
	// HTTPClient overrides the HTTP client used for discovery, JWKS and token requests.
	HTTPClient http.Client
}

// Provider is a generic OIDC authorization-code provider.
type Provider struct {
	config Config
	httpc  http.Client

	mu       sync.Mutex
	metadata *providerMetadata
	keys     []jwksKey
	keysAt   time.Time
}

// LogoutProvider extends Provider with RP-initiated logout for IdPs that support an OIDC
// end_session_endpoint.
type LogoutProvider struct {
	*Provider
}

// providerMetadata is the subset of the OIDC discovery document the provider uses.
type providerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// New creates a generic OIDC provider.
func New(config Config) *Provider {
	if len(config.Scopes) == 0 {
		config.Scopes = []string{"openid", "profile", "email"}
	} else if !slices.Contains(config.Scopes, "openid") {
		config.Scopes = append([]string{"openid"}, config.Scopes...)
	}

	httpc := config.HTTPClient
	if httpc == nil {
		// 10 second limit and 1MB body size
		httpc = http.NewClient(http.Timeout(10*time.Second), http.MaxResponseBody(1<<20))
	}

	return &Provider{config: config, httpc: httpc}
}

// endpoints returns the effective endpoint set, fetching the discovery document on first use
// unless every used endpoint is overridden.
func (p *Provider) endpoints(ctx context.Context) (*providerMetadata, error) {
	p.mu.Lock()
	md := p.metadata
	p.mu.Unlock()

	if md != nil {
		return md, nil
	}

	md = &providerMetadata{
		Issuer:                p.config.Issuer,
		AuthorizationEndpoint: p.config.AuthorizationEndpoint,
		TokenEndpoint:         p.config.TokenEndpoint,
		JWKSURI:               p.config.JWKSURI,
		EndSessionEndpoint:    p.config.EndSessionEndpoint,
	}

	if md.AuthorizationEndpoint == "" || md.TokenEndpoint == "" || md.JWKSURI == "" {
		fetched := providerMetadata{}

		uri := strings.TrimRight(p.config.Issuer, "/") + "/.well-known/openid-configuration"
		if err := p.httpc.WithContext(ctx).GetJSON(uri, &fetched); err != nil {
			return nil, fmt.Errorf("oidc: discovery failed: %w", err)
		}

		if md.AuthorizationEndpoint == "" {
			md.AuthorizationEndpoint = fetched.AuthorizationEndpoint
		}

		if md.TokenEndpoint == "" {
			md.TokenEndpoint = fetched.TokenEndpoint
		}

		if md.JWKSURI == "" {
			md.JWKSURI = fetched.JWKSURI
		}

		if md.EndSessionEndpoint == "" {
			md.EndSessionEndpoint = fetched.EndSessionEndpoint
		}
	}

	if md.AuthorizationEndpoint == "" || md.TokenEndpoint == "" || md.JWKSURI == "" {
		return nil, errors.New("oidc: discovery document is missing required endpoints")
	}

	p.mu.Lock()
	if p.metadata == nil {
		p.metadata = md
	}

	md = p.metadata
	p.mu.Unlock()

	return md, nil
}

// AuthURL implements provider.Provider.
func (p *Provider) AuthURL(ctx context.Context, state, nonce, codeChallenge string) (string, error) {
	md, err := p.endpoints(ctx)
	if err != nil {
		return "", err
	}

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.config.ClientID},
		"redirect_uri":          {p.config.RedirectURL},
		"scope":                 {strings.Join(p.config.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	maps.Copy(q, p.config.AuthParams)

	sep := "?"
	if strings.Contains(md.AuthorizationEndpoint, "?") {
		sep = "&"
	}

	return md.AuthorizationEndpoint + sep + q.Encode(), nil
}

// Exchange redeems the code and fully validates the returned id_token (signature/iss/aud/exp/nonce) before returning its claims.
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier, nonce string) (*provider.Tokens, error) {
	md, err := p.endpoints(ctx)
	if err != nil {
		return nil, err
	}

	form := map[string][]string{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.config.RedirectURL},
		"client_id":     {p.config.ClientID},
		"code_verifier": {codeVerifier},
	}

	if p.config.ClientSecret != "" {
		form["client_secret"] = []string{p.config.ClientSecret}
	}

	body, err := p.httpc.WithContext(ctx).PostForm(md.TokenEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("oidc: token exchange failed: %w", err)
	}

	var tr struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("oidc: invalid token response: %w", err)
	}

	if tr.IDToken == "" {
		return nil, errors.New("oidc: token response contains no id_token")
	}

	claims, err := p.verifyIDToken(ctx, md, tr.IDToken, nonce)
	if err != nil {
		return nil, err
	}

	tokens := &provider.Tokens{
		IDToken:      tr.IDToken,
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		RawClaims:    claims,
	}

	if tr.ExpiresIn > 0 {
		tokens.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}

	return tokens, nil
}

// verifyIDToken validates the id_token signature against the provider JWKS and its
// iss/aud/azp/exp/nbf/nonce claims.
func (p *Provider) verifyIDToken(ctx context.Context, md *providerMetadata, idToken, nonce string) (map[string]any, error) {
	claims := jwt.MapClaims{}

	_, err := jwt.ParseWithClaims(idToken, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)

		return p.verificationKey(ctx, md, kid)
	}, jwt.WithValidMethods(signingAlgorithms), jwt.WithLeeway(p.config.ClockSkew), jwt.WithExpirationRequired())
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token validation failed: %w", err)
	}

	iss, _ := claims["iss"].(string)

	if p.config.IssuerCheck != nil {
		if err := p.config.IssuerCheck(iss); err != nil {
			return nil, fmt.Errorf("oidc: id_token validation failed: %w", err)
		}
	} else if iss != md.Issuer {
		return nil, fmt.Errorf("oidc: id_token issuer %q does not match %q", iss, md.Issuer)
	}

	aud, err := claims.GetAudience()
	if err != nil || !slices.Contains(aud, p.config.ClientID) {
		return nil, errors.New("oidc: id_token audience does not contain the client_id")
	}

	if azp, ok := claims["azp"].(string); ok && azp != p.config.ClientID {
		return nil, errors.New("oidc: id_token azp does not match the client_id")
	}

	if got, _ := claims["nonce"].(string); got != nonce {
		return nil, errors.New("oidc: id_token nonce mismatch")
	}

	return claims, nil
}

// verificationKey returns the JWKS keys an id_token may be verified with.
func (p *Provider) verificationKey(ctx context.Context, md *providerMetadata, kid string) (any, error) {
	p.mu.Lock()
	candidates := p.candidateKeys(kid)
	stale := len(candidates) == 0 && time.Since(p.keysAt) >= time.Minute

	if stale {
		p.keysAt = time.Now()
	}

	p.mu.Unlock()

	// An unknown kid may trigger a JWKS refetch at most once a minute.
	if stale {
		keys, err := fetchJWKS(ctx, p.httpc, md.JWKSURI)
		if err != nil {
			return nil, err
		}

		p.mu.Lock()
		p.keys = keys
		candidates = p.candidateKeys(kid)
		p.mu.Unlock()
	}

	switch {
	case len(candidates) > 0:
		return jwt.VerificationKeySet{Keys: candidates}, nil
	case kid == "":
		return nil, errors.New("oidc: id_token has no kid and the JWKS has no usable keys")
	default:
		return nil, fmt.Errorf("oidc: no key for kid %q", kid)
	}
}

func (p *Provider) candidateKeys(kid string) []jwt.VerificationKey {
	var out []jwt.VerificationKey

	for _, k := range p.keys {
		if kid == "" || k.kid == kid {
			out = append(out, k.public)
		}
	}

	return out
}

// LogoutURL implements provider.Logouter.
func (p *LogoutProvider) LogoutURL(ctx context.Context, idTokenHint, state, postLogoutRedirectURI string) (string, error) {
	md, err := p.endpoints(ctx)
	if err != nil {
		return "", err
	}

	if md.EndSessionEndpoint == "" {
		return "", errors.New("oidc: provider has no end_session_endpoint")
	}

	q := url.Values{
		"post_logout_redirect_uri": {postLogoutRedirectURI},
		"state":                    {state},
	}

	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}

	sep := "?"
	if strings.Contains(md.EndSessionEndpoint, "?") {
		sep = "&"
	}

	return md.EndSessionEndpoint + sep + q.Encode(), nil
}
