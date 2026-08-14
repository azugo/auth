package jti

import (
	"context"
	"time"

	"azugo.io/core/cache"
)

// DenyList records JTIs that may no longer be used: revoked JWT access tokens (RFC 7009) and
// already-seen client_assertion JTIs (replay defence).
type DenyList interface {
	// Deny marks jti as unusable until ttl elapses.
	Deny(ctx context.Context, jti string, ttl time.Duration) error
	// Denied returns true when jti has been denied.
	Denied(ctx context.Context, jti string) (bool, error)
}

type cacheDenyList struct {
	c cache.Instance[bool]
}

// NewCacheDenyList creates the default cache-backed DenyList under the given instance name.
func NewCacheDenyList(c *cache.Cache, name string) (DenyList, error) {
	inst, err := cache.Create[bool](c, name)
	if err != nil {
		return nil, err
	}

	return &cacheDenyList{c: inst}, nil
}

// Deny marks jti as unusable until ttl elapses.
func (s *cacheDenyList) Deny(ctx context.Context, jti string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}

	return s.c.Set(ctx, jti, true, cache.TTL[bool](ttl))
}

// Denied returns true when jti has been denied.
func (s *cacheDenyList) Denied(ctx context.Context, jti string) (bool, error) {
	return s.c.Get(ctx, jti)
}
