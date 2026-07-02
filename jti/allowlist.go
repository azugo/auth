// Package jti implements the JTI (JWT/token ID) allowlist that backs token revocation and
// session-bound replay detection.
package jti

import (
	"context"
	"errors"
	"time"

	"azugo.io/core/cache"
)

// cacheInstanceName namespaces the allowlist within the shared cache.
const cacheInstanceName = "auth.jti"

// Store manages the JTI allowlist.
type Store interface {
	// Issue registers jti as valid for sessionID with the given TTL.
	Issue(ctx context.Context, jti, sessionID string, ttl time.Duration) error
	// Rotate atomically replaces oldJTI with newJTI for sessionID. Return false (no error)
	// when oldJTI is absent or belongs to a different session.
	Rotate(ctx context.Context, oldJTI, newJTI, sessionID string, ttl time.Duration) (bool, error)
	// Revoke removes jti from the allowlist.
	Revoke(ctx context.Context, jti string) error
	// Validate returns true when jti exists in the allowlist and belongs to sessionID.
	Validate(ctx context.Context, jti, sessionID string) (bool, error)
}

// cacheStore is the default Store backed by azugo.io/core/cache. Entries map jti → sessionID
// with a TTL equal to the remaining token lifetime. It is unexported because it adds nothing
// beyond the Store interface; NewCacheStore returns it as a Store.
type cacheStore struct {
	c cache.Instance[string]
}

// NewCacheStore creates the default cache-backed JTI Store using the app's cache.
func NewCacheStore(c *cache.Cache) (Store, error) {
	inst, err := cache.Create[string](c, cacheInstanceName)
	if err != nil {
		return nil, err
	}

	return &cacheStore{c: inst}, nil
}

// Issue registers jti as valid for sessionID with the given TTL.
func (s *cacheStore) Issue(ctx context.Context, jti, sessionID string, ttl time.Duration) error {
	return s.c.Set(ctx, jti, sessionID, cache.TTL[string](ttl))
}

// Rotate atomically replaces oldJTI with newJTI for sessionID. Return false (no error)
// when oldJTI is absent or belongs to a different session.
func (s *cacheStore) Rotate(ctx context.Context, oldJTI, newJTI, sessionID string, ttl time.Duration) (bool, error) {
	prev, err := s.c.Pop(ctx, oldJTI)
	if err != nil {
		var knf cache.KeyNotFoundError
		if errors.As(err, &knf) {
			return false, nil
		}

		return false, err
	}

	if prev != sessionID {
		return false, nil
	}

	if err := s.c.Set(ctx, newJTI, sessionID, cache.TTL[string](ttl)); err != nil {
		return false, err
	}

	return true, nil
}

// Revoke removes jti from the allowlist.
func (s *cacheStore) Revoke(ctx context.Context, jti string) error {
	return s.c.Delete(ctx, jti)
}

// Validate returns true when jti exists in the allowlist and belongs to sessionID.
func (s *cacheStore) Validate(ctx context.Context, jti, sessionID string) (bool, error) {
	id, err := s.c.Get(ctx, jti)
	if err != nil {
		return false, err
	}

	return id != "" && id == sessionID, nil
}
