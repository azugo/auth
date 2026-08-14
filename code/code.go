// Package code implements the single-use authorization codes minted by GET /authorize and
// redeemed by the authorization_code grant at POST /token.
package code

import (
	"context"
	"errors"
	"time"

	"azugo.io/core/cache"
)

// Cache instance names for live codes, redeemed codes and issued-token bindings.
const (
	cacheInstanceName  = "auth:code"
	usedInstanceName   = "auth:code:used"
	issuedInstanceName = "auth:code:token"
)

var (
	// ErrNotFound is returned by Consume when no code matches.
	ErrNotFound = errors.New("authorization code not found")
	// ErrReplayed is returned by Consume, together with the bound record, when the code was
	// already redeemed.
	ErrReplayed = errors.New("authorization code replayed")
)

// AuthorizationCode is the server-side record bound to an issued code.
type AuthorizationCode struct {
	// Code is the opaque high-entropy value returned to the client.
	Code     string
	ClientID string
	UserID   string
	// SessionID is the session established at /authorize; validated again on redemption.
	SessionID string
	// RedirectURI must exactly match the redirect_uri presented at /token.
	RedirectURI string
	Scope       string
	// Nonce is echoed into the id_token.
	Nonce string
	// ACRValues are the requested acr_values, enforced again at redemption.
	ACRValues []string
	// CodeChallenge is the PKCE S256 challenge; "" when the client did not use PKCE.
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	// IssuedTokenID and IssuedTokenExpiresAt identify the JWT access token issued at
	// redemption so a replay can revoke it. Populated only on the ErrReplayed record.
	IssuedTokenID        string
	IssuedTokenExpiresAt time.Time
}

// Store persists single-use authorization codes.
type Store interface {
	// Save persists a freshly minted code.
	Save(ctx context.Context, c *AuthorizationCode) error
	// Consume atomically fetches and deletes the code. It returns ErrNotFound for an unknown
	// or expired code, or the redeemed record with ErrReplayed when the code was already
	// consumed.
	Consume(ctx context.Context, code string) (*AuthorizationCode, error)
	// BindIssuedToken records the JWT access token issued for a redeemed code so a later
	// replay can revoke it.
	BindIssuedToken(ctx context.Context, code, tokenID string, expiresAt time.Time) error
}

type issuedToken struct {
	ID        string
	ExpiresAt time.Time
}

// cacheStore is the default Store backed by cache.
type cacheStore struct {
	codes  cache.Instance[AuthorizationCode]
	used   cache.Instance[AuthorizationCode]
	issued cache.Instance[issuedToken]
	// tombstoneTTL is how long a redeemed code is remembered for replay detection.
	tombstoneTTL time.Duration
}

// NewCacheStore creates the default cache-backed code Store using the app's cache.
func NewCacheStore(c *cache.Cache, codeTTL time.Duration) (Store, error) {
	codes, err := cache.Create[AuthorizationCode](c, cacheInstanceName)
	if err != nil {
		return nil, err
	}

	used, err := cache.Create[AuthorizationCode](c, usedInstanceName)
	if err != nil {
		return nil, err
	}

	issued, err := cache.Create[issuedToken](c, issuedInstanceName)
	if err != nil {
		return nil, err
	}

	return &cacheStore{codes: codes, used: used, issued: issued, tombstoneTTL: codeTTL}, nil
}

// Save persists a freshly minted code with a TTL equal to its remaining lifetime.
func (s *cacheStore) Save(ctx context.Context, c *AuthorizationCode) error {
	return s.codes.Set(ctx, c.Code, *c, cache.TTL[AuthorizationCode](time.Until(c.ExpiresAt)))
}

// Consume atomically fetches and deletes the code, leaving a replay tombstone.
func (s *cacheStore) Consume(ctx context.Context, code string) (*AuthorizationCode, error) {
	rec, err := s.codes.Pop(ctx, code)
	if err != nil {
		var knf cache.KeyNotFoundError
		if !errors.As(err, &knf) {
			return nil, err
		}

		if used, uerr := s.used.Get(ctx, code); uerr == nil && used.Code != "" {
			if tok, terr := s.issued.Get(ctx, code); terr == nil && tok.ID != "" {
				used.IssuedTokenID = tok.ID
				used.IssuedTokenExpiresAt = tok.ExpiresAt
			}

			return &used, ErrReplayed
		}

		return nil, ErrNotFound
	}

	_ = s.used.Set(ctx, code, rec, cache.TTL[AuthorizationCode](s.tombstoneTTL))

	if time.Now().After(rec.ExpiresAt) {
		return nil, ErrNotFound
	}

	return &rec, nil
}

// BindIssuedToken records the access token issued for a redeemed code.
func (s *cacheStore) BindIssuedToken(ctx context.Context, code, tokenID string, expiresAt time.Time) error {
	return s.issued.Set(ctx, code, issuedToken{ID: tokenID, ExpiresAt: expiresAt}, cache.TTL[issuedToken](s.tombstoneTTL))
}
