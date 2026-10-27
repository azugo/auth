// Package dpop validates DPoP proofs (RFC 9449) that bind access tokens to a client's key pair.
package dpop

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"

	"azugo.io/auth/jti"
	"azugo.io/auth/token"

	"azugo.io/azugo"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
)

// HeaderName is the request header carrying the proof and the Authorization scheme of a bound token.
const HeaderName = "DPoP"

// NonceHeaderName is the response header carrying the server nonce.
const NonceHeaderName = "DPoP-Nonce"

// proofType is the typ header of a DPoP proof.
const proofType = "dpop+jwt"

var (
	// ErrInvalidProof is returned for a proof that fails validation.
	ErrInvalidProof = errors.New("invalid DPoP proof")
	// ErrUseNonce is returned when the proof lacks a current server nonce.
	ErrUseNonce = errors.New("DPoP nonce required")
)

// Algorithms are the asymmetric JWS algorithms accepted for proofs.
var Algorithms = []string{"ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "EdDSA"}

// ProofOption adds a requirement to ValidateProof.
type ProofOption interface {
	apply(o *proofOptions)
}

type proofOptions struct {
	ath    string
	nonces *Nonces
	skew   time.Duration
}

// ATH requires the proof's ath claim to be the hash of this access token.
type ATH string

func (o ATH) apply(opts *proofOptions) {
	opts.ath = Hash(string(o))
}

// ClockSkew is how far the proof's iat may lie from the current time, 0 without it. With Nonces
// it bounds only an iat in the future.
type ClockSkew time.Duration

func (o ClockSkew) apply(opts *proofOptions) {
	opts.skew = time.Duration(o)
}

// Nonces issues server nonces, an HMAC-SHA256 under Key of the current Window, accepting the
// previous window's too. As a proof option it requires one in the proof, which then bounds the
// proof's age in place of its iat, so a client clock running late does not matter.
type Nonces struct {
	Key []byte
	// Window is how long a nonce stays current; without a positive one no nonce is valid.
	Window time.Duration
}

func (n Nonces) apply(opts *proofOptions) {
	opts.nonces = &n
}

// New returns the nonce of the current window, "" without a positive Window.
func (n Nonces) New() string {
	if n.Window <= 0 {
		return ""
	}

	return n.at(time.Now().UnixNano() / int64(n.Window))
}

// expiry returns when nonce stops being accepted, false when it is not current.
func (n Nonces) expiry(nonce string) (time.Time, bool) {
	if n.Window <= 0 {
		return time.Time{}, false
	}

	w := n.Window
	idx := time.Now().UnixNano() / int64(w)

	for _, i := range []int64{idx, idx - 1} {
		if hmac.Equal([]byte(nonce), []byte(n.at(i))) {
			return time.Unix(0, (i+2)*int64(w)), true
		}
	}

	return time.Time{}, false
}

// at returns the nonce of window idx.
func (n Nonces) at(idx int64) string {
	mac := hmac.New(sha256.New, n.Key)
	_ = binary.Write(mac, binary.BigEndian, idx)

	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ValidateProof verifies a DPoP proof for the request method and uri, records its jti in replay
// and returns the JWK SHA-256 thumbprint of the proof key.
func ValidateProof(ctx context.Context, proof, method, uri string, replay jti.DenyList, opts ...ProofOption) (string, error) {
	var o proofOptions
	for _, opt := range opts {
		opt.apply(&o)
	}

	var jkt string

	claims := jwt.MapClaims{}

	if _, err := jwt.ParseWithClaims(proof, claims,
		func(t *jwt.Token) (any, error) {
			if typ, _ := t.Header["typ"].(string); typ != proofType {
				return nil, ErrInvalidProof
			}

			pub, thumbprint, err := parseJWK(t.Header["jwk"])
			if err != nil {
				return nil, err
			}

			jkt = thumbprint

			return pub, nil
		},
		jwt.WithValidMethods(Algorithms),
	); err != nil {
		return "", ErrInvalidProof
	}

	if htm, _ := claims["htm"].(string); htm != method {
		return "", ErrInvalidProof
	}

	if htu, _ := claims["htu"].(string); !sameURI(htu, uri) {
		return "", ErrInvalidProof
	}

	id, _ := claims["jti"].(string)
	if id == "" || len(id) > 256 {
		return "", ErrInvalidProof
	}

	iat, err := claims.GetIssuedAt()
	if err != nil || iat == nil {
		return "", ErrInvalidProof
	}

	if o.ath != "" {
		if ath, _ := claims["ath"].(string); subtle.ConstantTimeCompare([]byte(ath), []byte(o.ath)) != 1 {
			return "", ErrInvalidProof
		}
	}

	// A proof from the future is refused even with a nonce (FAPI 2.0).
	if time.Until(iat.Time) > o.skew {
		return "", ErrInvalidProof
	}

	// iat has whole-second precision, so a just-signed proof may look up to a second old.
	expires := iat.Add(o.skew + time.Second)

	if o.nonces != nil {
		nonce, _ := claims["nonce"].(string)

		var ok bool
		if expires, ok = o.nonces.expiry(nonce); !ok {
			return "", ErrUseNonce
		}
	} else if time.Now().After(expires) {
		return "", ErrInvalidProof
	}

	fresh, err := replay.Claim(ctx, jkt+":"+id, time.Until(expires))
	if err != nil {
		return "", err
	}

	if !fresh {
		return "", ErrInvalidProof
	}

	return jkt, nil
}

// Credential returns the token of a Bearer or DPoP Authorization header and whether its scheme is
// DPoP; any other header reads as no token.
func Credential(header string) (string, bool) {
	scheme, tok, _ := strings.Cut(header, " ")

	switch {
	case tok == "":
		return "", false
	case strings.EqualFold(scheme, HeaderName):
		return tok, true
	case strings.EqualFold(scheme, "Bearer"):
		return tok, false
	default:
		return "", false
	}
}

// RequestURL returns the public URL of the request without its query, under baseURL when set
// instead of the one the request was received at.
func RequestURL(ctx *azugo.Context, baseURL string) string {
	path := string(ctx.Request().URI().PathOriginal())
	if path == "" {
		path = "/"
	}

	if base := ctx.BasePath(); len(path) >= len(base) && strings.EqualFold(path[:len(base)], base) && (len(path) == len(base) || path[len(base)] == '/') {
		path = path[len(base):]
	}

	if baseURL == "" {
		baseURL = ctx.BaseURL()
	}

	return strings.TrimRight(baseURL, "/") + path
}

// Hash returns base64url(SHA-256(value)), the form of the ath claim.
func Hash(value string) string {
	sum := sha256.Sum256([]byte(value))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// jwk holds the public members of a JSON Web Key.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
	D   string `json:"d"`
	K   string `json:"k"`
}

// parseJWK parses a public JWK header value into a key and its thumbprint.
func parseJWK(v any) (any, string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, "", ErrInvalidProof
	}

	var k jwk
	if err := json.Unmarshal(raw, &k); err != nil || k.D != "" || k.K != "" {
		return nil, "", ErrInvalidProof
	}

	var pub crypto.PublicKey

	switch k.Kty {
	case "EC":
		pub, err = ecKey(k)
	case "RSA":
		pub, err = rsaKey(k)
	case "OKP":
		pub, err = okpKey(k)
	default:
		err = ErrInvalidProof
	}

	if err != nil {
		return nil, "", ErrInvalidProof
	}

	// The parsers accept only minimal encodings, so the thumbprint of the parsed key is the one
	// over the members as sent.
	jkt, err := token.Thumbprint(pub)
	if err != nil {
		return nil, "", ErrInvalidProof
	}

	return pub, jkt, nil
}

func ecKey(k jwk) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve

	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, ErrInvalidProof
	}

	size := (curve.Params().BitSize + 7) / 8

	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(x) != size {
		return nil, ErrInvalidProof
	}

	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil || len(y) != size {
		return nil, ErrInvalidProof
	}

	// The uncompressed point encoding lets the standard library check the point is on the curve.
	return ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
}

func rsaKey(k jwk) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil || len(n) < 256 || n[0] == 0 {
		return nil, ErrInvalidProof
	}

	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil || len(e) == 0 || len(e) > 4 || e[0] == 0 {
		return nil, ErrInvalidProof
	}

	exp := new(big.Int).SetBytes(e)
	if exp.Int64() < 3 || exp.Bit(0) == 0 {
		return nil, ErrInvalidProof
	}

	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}, nil
}

func okpKey(k jwk) (ed25519.PublicKey, error) {
	if k.Crv != "Ed25519" {
		return nil, ErrInvalidProof
	}

	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(x) != ed25519.PublicKeySize {
		return nil, ErrInvalidProof
	}

	return ed25519.PublicKey(x), nil
}

// sameURI reports whether the htu claim names uri, ignoring query and fragment.
func sameURI(htu, uri string) bool {
	a, err := url.Parse(htu)
	if err != nil || !a.IsAbs() {
		return false
	}

	b, err := url.Parse(uri)
	if err != nil {
		return false
	}

	return strings.EqualFold(a.Scheme, b.Scheme) &&
		hostPort(a) == hostPort(b) &&
		cmpPath(a) == cmpPath(b)
}

// hostPort returns the lower-cased host with the scheme's default port dropped.
func hostPort(u *url.URL) string {
	host := strings.ToLower(u.Hostname())

	port := u.Port()
	if port == "" ||
		(port == "443" && strings.EqualFold(u.Scheme, "https")) ||
		(port == "80" && strings.EqualFold(u.Scheme, "http")) {
		return host
	}

	return host + ":" + port
}

func cmpPath(u *url.URL) string {
	if p := u.EscapedPath(); p != "" {
		return p
	}

	return "/"
}
