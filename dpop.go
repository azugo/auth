package auth

import (
	"context"
	"errors"
	"strings"

	"azugo.io/auth/client"
	"azugo.io/auth/dpop"
	"azugo.io/auth/token"

	"azugo.io/azugo"
	"azugo.io/core/http"
)

// tokenTypeDPoP is the RFC 9449 token_type and Authorization scheme of a DPoP-bound token.
const tokenTypeDPoP = "DPoP"

// DPoPProof is a DPoP proof presented with a request.
type DPoPProof struct {
	// Proof is the DPoP header value.
	Proof string
	// Method and URL are the HTTP method and URL of the request the proof was sent with.
	Method string
	URL    string
}

// ReadDPoPProof returns the DPoP proof sent with the request, nil without one.
func (a *Auth) ReadDPoPProof(ctx *azugo.Context) (*DPoPProof, error) {
	values := ctx.Request().Header.PeekAll(dpop.HeaderName)

	switch len(values) {
	case 0:
		return nil, nil //nolint:nilnil
	case 1:
		return &DPoPProof{Proof: string(values[0]), Method: string(ctx.Method()), URL: dpop.RequestURL(ctx, a.config.BaseURL)}, nil
	default:
		return nil, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidDPoPProof, "multiple DPoP proofs")
	}
}

// DPoPNonce returns the current server nonce for the DPoP proofs of a client.DPoPPolicyNonce client.
func (a *Auth) DPoPNonce() string {
	return a.nonces.New()
}

// clientDPoPNonce returns the server nonce to hand cl, "" when it does not require one.
func (a *Auth) clientDPoPNonce(cl *client.Client) string {
	if cl.DPoPPolicy != client.DPoPPolicyNonce {
		return ""
	}

	return a.DPoPNonce()
}

// verifyDPoP validates the proof presented at a token-issuing endpoint and returns its key
// thumbprint, "" without a proof.
func (a *Auth) verifyDPoP(ctx context.Context, cl *client.Client, proof *DPoPProof) (string, error) {
	if proof == nil {
		if cl.DPoPRequired() {
			return "", &OAuthError{
				Code:        ErrCodeInvalidDPoPProof,
				Description: "DPoP proof required",
				status:      http.StatusBadRequest,
				dpopNonce:   a.clientDPoPNonce(cl),
			}
		}

		return "", nil
	}

	opts := []dpop.ProofOption{dpop.ClockSkew(a.config.DPoPProofWindow)}
	if cl.DPoPPolicy == client.DPoPPolicyNonce {
		opts = append(opts, a.nonces)
	}

	jkt, err := dpop.ValidateProof(ctx, proof.Proof, proof.Method, proof.URL, a.proofs, opts...)

	switch {
	case errors.Is(err, dpop.ErrUseNonce):
		return "", &OAuthError{
			Code:        ErrCodeUseDPoPNonce,
			Description: "DPoP proof must carry the server nonce",
			status:      http.StatusBadRequest,
			dpopNonce:   a.DPoPNonce(),
		}
	case errors.Is(err, dpop.ErrInvalidProof):
		return "", NewOAuthError(http.StatusBadRequest, ErrCodeInvalidDPoPProof, "invalid DPoP proof")
	case err != nil:
		return "", NewOAuthErrorFrom(err)
	}

	return jkt, nil
}

// ReadAccessToken returns the access token of a Bearer or DPoP Authorization header once its DPoP
// binding holds. It returns "" without such a header. The proof is single use, so a request is
// read this way once, by middleware.DPoP or middleware.Auth; handlers behind them use
// ReadSessionToken.
func (a *Auth) ReadAccessToken(ctx *azugo.Context) (string, error) {
	tok, _ := dpop.Credential(ctx.Header.Get(http.HeaderAuthorization))
	if tok == "" {
		return "", nil
	}

	jkt, err := a.boundKey(ctx, tok)
	if err != nil {
		return "", err
	}

	if err := a.VerifyDPoPBinding(ctx, tok, jkt); err != nil {
		return "", err
	}

	return tok, nil
}

// VerifyDPoPBinding checks the Authorization header presenting tok, bound to the key thumbprint
// jkt or unbound when "", holds its DPoP binding: a bound token needs the DPoP scheme and a proof
// by its key, an unbound one the Bearer scheme.
func (a *Auth) VerifyDPoPBinding(ctx *azugo.Context, tok, jkt string) error {
	if _, bound := dpop.Credential(ctx.Header.Get(http.HeaderAuthorization)); !bound {
		if jkt != "" {
			return NewDPoPError(ErrCodeInvalidToken, "DPoP-bound token presented as a bearer token")
		}

		return nil
	}

	if jkt == "" {
		return NewDPoPError(ErrCodeInvalidToken, "token is not DPoP-bound")
	}

	proof, err := a.ReadDPoPProof(ctx)
	if oe, ok := errors.AsType[*OAuthError](err); ok {
		return NewDPoPError(oe.Code, oe.Description)
	}

	if proof == nil {
		return NewDPoPError(ErrCodeInvalidDPoPProof, "DPoP proof required")
	}

	got, err := dpop.ValidateProof(ctx, proof.Proof, proof.Method, proof.URL, a.proofs, dpop.ATH(tok), dpop.ClockSkew(a.config.DPoPProofWindow))

	switch {
	case errors.Is(err, dpop.ErrInvalidProof):
		return NewDPoPError(ErrCodeInvalidDPoPProof, "invalid DPoP proof")
	case err != nil:
		return NewOAuthErrorFrom(err)
	case got != jkt:
		return NewDPoPError(ErrCodeInvalidDPoPProof, "DPoP proof key does not match the token")
	}

	return nil
}

// boundKey returns the DPoP key thumbprint tok is bound to, "" when unbound or unreadable.
func (a *Auth) boundKey(ctx context.Context, tok string) (string, error) {
	if strings.HasPrefix(tok, pasetoPrefix) {
		access, _, err := a.codec.Decode(tok)
		if err != nil || access == nil || access.Confirmation == nil {
			return "", nil //nolint:nilerr
		}

		return access.Confirmation.JKT, nil
	}

	// A JWT's binding is read only once its signature holds, so a forged one costs no proof work.
	if a.keys == nil {
		return "", nil
	}

	set, err := a.keys.KeySet(ctx)
	if err != nil {
		return "", NewOAuthErrorFrom(err)
	}

	claims, err := token.VerifyAccessToken(set, tok)
	if err != nil {
		return "", nil //nolint:nilerr
	}

	return claims.JKT, nil
}

// tokenType returns the token_type of an access token bound to jkt.
func tokenType(jkt string) string {
	if jkt != "" {
		return tokenTypeDPoP
	}

	return tokenTypeBearer
}

// confirmation returns the cnf claim of an access token bound to jkt.
func confirmation(jkt string) *token.Confirmation {
	if jkt == "" {
		return nil
	}

	return &token.Confirmation{JKT: jkt}
}
