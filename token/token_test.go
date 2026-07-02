package token

import (
	"strings"
	"testing"
	"time"

	"azugo.io/auth/contract"

	"github.com/go-quicktest/qt"
)

func testSecret(b byte) string {
	return strings.Repeat(string(rune(b)), 32)
}

// codecFor builds a Codec whose Configuration has the given current + fallback secrets.
func codecFor(secret string, fallback ...string) *Codec {
	return NewCodec(&contract.Configuration{Secret: secret, FallbackSecrets: fallback})
}

func TestAccessTokenRoundTrip(t *testing.T) {
	c := codecFor(testSecret('a'))

	now := time.Now().Unix()
	claims := AccessClaims{
		Type:      TypeAccessToken,
		SessionID: "sid-1",
		TokenID:   "jti-1",
		IssuedAt:  now,
		ExpiresAt: now + 1800,
	}

	tok, err := c.Encrypt(claims)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(strings.HasPrefix(tok, "v4.local.")))

	got, err := c.DecodeAccess(tok)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.Type, TypeAccessToken))
	qt.Check(t, qt.Equals(got.SessionID, "sid-1"))
	qt.Check(t, qt.Equals(got.TokenID, "jti-1"))
	qt.Check(t, qt.Equals(got.ExpiresAt, now+1800))
}

func TestDecryptWrongSecretFails(t *testing.T) {
	tok, err := codecFor(testSecret('a')).Encrypt(AccessClaims{Type: TypeAccessToken, SessionID: "sid"})
	qt.Assert(t, qt.IsNil(err))

	// A codec with a different secret (and no matching fallback) cannot open it.
	_, err = codecFor(testSecret('b')).DecodeAccess(tok)
	qt.Check(t, qt.ErrorIs(err, ErrInvalidToken))
}

func TestDecryptSecondarySecretFallback(t *testing.T) {
	old := testSecret('a')
	current := testSecret('b')

	// Token sealed with the now-retired secret.
	tok, err := codecFor(old).Encrypt(AccessClaims{Type: TypeSessionCookie, SessionID: "sid"})
	qt.Assert(t, qt.IsNil(err))

	// Current secret first, retired secret kept as a fallback for verification.
	got, err := codecFor(current, old).DecodeAccess(tok)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.Type, TypeSessionCookie))
	qt.Check(t, qt.Equals(got.SessionID, "sid"))
}

func TestKIDIsPASERKLidStablePerSecret(t *testing.T) {
	c := codecFor(testSecret('a'))

	kid := c.derive(testSecret('a')).kid
	qt.Check(t, qt.IsTrue(strings.HasPrefix(kid, "k4.lid.")))
	qt.Check(t, qt.Equals(c.derive(testSecret('a')).kid, kid))         // stable for the same secret
	qt.Check(t, qt.Not(qt.Equals(c.derive(testSecret('b')).kid, kid))) // differs across secrets
}

func TestAPIKeyTokenTypeDiscrimination(t *testing.T) {
	c := codecFor(testSecret('a'))

	tok, err := c.Encrypt(APIKeyClaims{Type: TypeAPIKey, KeyID: "key-1"})
	qt.Assert(t, qt.IsNil(err))

	got, err := c.DecodeAPIKey(tok)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.KeyID, "key-1"))

	// Decoding an api-key token as an access token must be rejected on the typ discriminator.
	_, err = c.DecodeAccess(tok)
	qt.Check(t, qt.ErrorIs(err, ErrUnexpectedTokenType))
}
