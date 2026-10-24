// Package token implements the PASETO v4.local tokens used by the auth library: short-lived
// access tokens, long-lived session cookies, and API-key tokens.
package token

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"sync"

	"azugo.io/auth/contract"

	"aidanwoods.dev/go-paseto"
	"github.com/goccy/go-json"
	"golang.org/x/crypto/blake2b"
)

// Token type discriminators carried in the "typ" claim.
const (
	TypeAccessToken   = "at" // short-lived introspect access token
	TypeSessionCookie = "sc" // long-lived session cookie
	TypeStepToken     = "st" // short-lived token bound to a pending (mid-step) session
	TypeAPIKey        = "ak" // API-key token
)

var (
	// ErrInvalidToken is returned when a token cannot be decrypted with any supplied secret.
	ErrInvalidToken = errors.New("invalid token")
	// ErrUnexpectedTokenType is returned by the typed decoders when the "typ" claim does not
	// match the expected token kind.
	ErrUnexpectedTokenType = errors.New("unexpected token type")
)

// Confirmation carries the DPoP JWK thumbprint (cnf.jkt, RFC 9449 §6.1). Present only when the
// token was issued with a DPoP proof.
//
// TODO: not implemented yet.
type Confirmation struct {
	JKT string `json:"jkt,omitempty"` // base64url(SHA-256(DPoP public key JWK))
}

// AccessClaims are the claims of introspect access tokens (typ="at") and session cookies
// (typ="sc").
type AccessClaims struct {
	Type         string        `json:"typ"`
	SessionID    string        `json:"sid"`
	TokenID      string        `json:"jti"`
	ClientID     string        `json:"cid,omitempty"`
	Scope        string        `json:"scope,omitempty"`
	IssuedAt     int64         `json:"iat"`
	ExpiresAt    int64         `json:"exp"`
	Confirmation *Confirmation `json:"cnf,omitempty"` // set when DPoP-bound
}

// APIKeyClaims are the claims of API-key tokens (typ="ak"). Their expiry is the stored key's.
type APIKeyClaims struct {
	Type   string `json:"typ"`
	KeyID  string `json:"kid"` // looked up in apikey.Store
	Secret string `json:"sec"` // matched against apikey.Key.Hash
}

type footer struct {
	// KID is the PASERK k4.lid
	KID string `json:"kid,omitempty"`
}

// Codec seals and opens PASETO v4.local tokens, reading Secret / FallbackSecrets from the
// Configuration it was built with.
type Codec struct {
	cfg    *contract.Configuration
	keys   sync.Map // secret string -> *derivedKey
	parser paseto.Parser
}

type derivedKey struct {
	key paseto.V4SymmetricKey
	kid string
	// footer is the pre-marshaled token footer carrying the kid.
	footer []byte
}

// NewCodec creates a token Codec with the given configuration.
func NewCodec(cfg *contract.Configuration) *Codec {
	return &Codec{cfg: cfg, parser: paseto.NewParserWithoutExpiryCheck()}
}

func (c *Codec) secrets() []string {
	out := make([]string, 0, 1+len(c.cfg.FallbackSecrets))

	if c.cfg.Secret != "" {
		out = append(out, c.cfg.Secret)
	}

	return append(out, c.cfg.FallbackSecrets...)
}

// derive returns the cached key + kid for secret, computing (and caching) them on first use.
func (c *Codec) derive(secret string) *derivedKey {
	if d, ok := c.keys.Load(secret); ok {
		dk, _ := d.(*derivedKey)

		return dk
	}

	sum := sha256.Sum256([]byte(secret))

	key, err := paseto.V4SymmetricKeyFromBytes(sum[:])
	if err != nil {
		panic(err)
	}

	// h is the PASERK k4.lid of the derived key.
	const h = "k4.lid."

	d, err := blake2b.New(33, nil)
	if err != nil {
		panic(err)
	}

	_, _ = d.Write([]byte(h + "k4.local." + base64.RawURLEncoding.EncodeToString(key.ExportBytes())))

	kid := h + base64.RawURLEncoding.EncodeToString(d.Sum(nil))

	ftr, err := json.Marshal(footer{KID: kid})
	if err != nil {
		panic(err)
	}

	dk := &derivedKey{key: key, kid: kid, footer: ftr}
	c.keys.Store(secret, dk)

	return dk
}

// Encrypt seals claims into a PASETO v4.local token with the current secret.
func (c *Codec) Encrypt(claims any) (string, error) {
	d := c.derive(c.cfg.Secret)

	data, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	tok, err := paseto.NewTokenFromClaimsJSON(data, d.footer)
	if err != nil {
		return "", err
	}

	return tok.V4Encrypt(d.key, nil), nil
}

func (c *Codec) decrypt(raw string) ([]byte, error) {
	secrets := c.secrets()
	if len(secrets) == 0 {
		return nil, ErrInvalidToken
	}

	// With multiple candidate secrets the footer kid selects which one to try first.
	if len(secrets) > 1 {
		if ftr, err := c.parser.UnsafeParseFooter(paseto.V4Local, raw); err == nil {
			var f footer
			if json.Unmarshal(ftr, &f) == nil && f.KID != "" {
				for i, s := range secrets {
					if c.derive(s).kid == f.KID {
						secrets[0], secrets[i] = secrets[i], secrets[0]

						break
					}
				}
			}
		}
	}

	for _, secret := range secrets {
		tok, err := c.parser.ParseV4Local(c.derive(secret).key, raw, nil)
		if err != nil {
			continue
		}

		return tok.ClaimsJSON(), nil
	}

	return nil, ErrInvalidToken
}

// DecodeAccess opens a token and decodes it as AccessClaims, accepting access and
// session-cookie tokens.
func (c *Codec) DecodeAccess(raw string) (*AccessClaims, error) {
	return c.decodeAccessClaims(raw, TypeAccessToken, TypeSessionCookie)
}

// DecodeSession opens a token and decodes it as AccessClaims, accepting access, session-cookie
// and step tokens alike.
func (c *Codec) DecodeSession(raw string) (*AccessClaims, error) {
	return c.decodeAccessClaims(raw, TypeAccessToken, TypeSessionCookie, TypeStepToken)
}

// DecodeSessionCookie opens a token and decodes it as AccessClaims, accepting only the
// session cookie.
func (c *Codec) DecodeSessionCookie(raw string) (*AccessClaims, error) {
	return c.decodeAccessClaims(raw, TypeSessionCookie)
}

// decodeAccessClaims opens a token as AccessClaims and requires its "typ" to be one of types.
func (c *Codec) decodeAccessClaims(raw string, types ...string) (*AccessClaims, error) {
	tc, err := c.open(raw)
	if err != nil {
		return nil, err
	}

	if !slices.Contains(types, tc.Type) {
		return nil, ErrUnexpectedTokenType
	}

	return &tc.AccessClaims, nil
}

// Decode opens a token once and decodes it as AccessClaims for an access or session-cookie
// token, or as APIKeyClaims for an API key token; exactly one of them is returned.
func (c *Codec) Decode(raw string) (*AccessClaims, *APIKeyClaims, error) {
	tc, err := c.open(raw)
	if err != nil {
		return nil, nil, err
	}

	switch tc.Type {
	case TypeAccessToken, TypeSessionCookie:
		return &tc.AccessClaims, nil, nil
	case TypeAPIKey:
		return nil, tc.apiKey(), nil
	default:
		return nil, nil, ErrUnexpectedTokenType
	}
}

// DecodeAPIKey opens a token and decodes it as APIKeyClaims.
func (c *Codec) DecodeAPIKey(raw string) (*APIKeyClaims, error) {
	tc, err := c.open(raw)
	if err != nil {
		return nil, err
	}

	if tc.Type != TypeAPIKey {
		return nil, ErrUnexpectedTokenType
	}

	return tc.apiKey(), nil
}

// tokenClaims holds the claims of every token type, so a token is unmarshaled once whatever its
// "typ".
type tokenClaims struct {
	AccessClaims

	KeyID  string `json:"kid"`
	Secret string `json:"sec"`
}

func (tc *tokenClaims) apiKey() *APIKeyClaims {
	return &APIKeyClaims{Type: tc.Type, KeyID: tc.KeyID, Secret: tc.Secret}
}

// open decrypts a token and unmarshals its claims.
func (c *Codec) open(raw string) (*tokenClaims, error) {
	claims, err := c.decrypt(raw)
	if err != nil {
		return nil, err
	}

	tc := &tokenClaims{}
	if err := json.Unmarshal(claims, tc); err != nil {
		return nil, err
	}

	return tc, nil
}
