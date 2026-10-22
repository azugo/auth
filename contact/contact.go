// Package contact persists the open contact verification requests, one per user, channel and
// address.
package contact

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"azugo.io/auth/reset"

	"azugo.io/core/cache"
)

// ErrNotFound is returned when no live verification request matches.
var ErrNotFound = errors.New("contact verification request not found")

// Store persists contact verification requests.
type Store interface {
	// Save persists request for channel until its expiration, replacing the request open for its
	// user on channel and identifier.
	Save(ctx context.Context, channel string, r *reset.Request) error
	// Get returns the live request, or ErrNotFound when it is unknown or expired.
	Get(ctx context.Context, id string) (*reset.Request, error)
	// Open returns the live request of user on channel for address, or ErrNotFound.
	Open(ctx context.Context, channel, userID, address string) (*reset.Request, error)
	// Consume atomically fetches and deletes the request. It returns ErrNotFound when the
	// request is unknown, expired or already consumed.
	Consume(ctx context.Context, id string) (*reset.Request, error)
}

// entry is a stored request with the channel it was opened on.
type entry struct {
	Channel string
	Request reset.Request
}

// cacheStore is the default Store backed by cache.
type cacheStore struct {
	requests cache.Instance[entry]
	// open maps a channel, user ID and address digest to the open request ID
	open cache.Instance[string]
}

// NewCacheStore creates the default cache-backed Store using the app's cache.
func NewCacheStore(c *cache.Cache) (Store, error) {
	requests, err := cache.Create[entry](c, "auth:contactverify")
	if err != nil {
		return nil, err
	}

	open, err := cache.Create[string](c, "auth:contactverify:open")
	if err != nil {
		return nil, err
	}

	return &cacheStore{requests: requests, open: open}, nil
}

// Save persists the request with a TTL equal to its remaining lifetime; an already expired
// request is not stored at all.
func (s *cacheStore) Save(ctx context.Context, channel string, r *reset.Request) error {
	ttl := time.Until(r.ExpiresAt)
	if ttl <= 0 {
		return nil
	}

	key := openKey(channel, r.UserID, r.Identifier)

	if prev, err := s.open.Get(ctx, key); err == nil && prev != "" && prev != r.ID {
		if err := s.requests.Delete(ctx, prev); err != nil {
			return err
		}
	}

	if err := s.requests.Set(ctx, r.ID, entry{Channel: channel, Request: *r}, cache.TTL[entry](ttl)); err != nil {
		return err
	}

	if err := s.open.Set(ctx, key, r.ID, cache.TTL[string](ttl)); err != nil {
		return err
	}

	if err := s.requests.Sync(ctx); err != nil {
		return err
	}

	return s.open.Sync(ctx)
}

// Get returns the live request.
func (s *cacheStore) Get(ctx context.Context, id string) (*reset.Request, error) {
	e, err := s.requests.Get(ctx, id)
	if err != nil {
		if _, ok := errors.AsType[cache.KeyNotFoundError](err); ok {
			return nil, ErrNotFound
		}

		return nil, err
	}

	// A missing key reads as the zero value.
	if e.Request.ID == "" || time.Now().After(e.Request.ExpiresAt) {
		return nil, ErrNotFound
	}

	return &e.Request, nil
}

// Open returns the live request of user on channel for address.
func (s *cacheStore) Open(ctx context.Context, channel, userID, address string) (*reset.Request, error) {
	id, err := s.open.Get(ctx, openKey(channel, userID, address))
	if err != nil {
		if _, ok := errors.AsType[cache.KeyNotFoundError](err); ok {
			return nil, ErrNotFound
		}

		return nil, err
	}

	if id == "" {
		return nil, ErrNotFound
	}

	return s.Get(ctx, id)
}

// Consume atomically fetches and deletes the request.
func (s *cacheStore) Consume(ctx context.Context, id string) (*reset.Request, error) {
	e, err := s.requests.Pop(ctx, id)
	if err != nil {
		if _, ok := errors.AsType[cache.KeyNotFoundError](err); ok {
			return nil, ErrNotFound
		}

		return nil, err
	}

	if e.Request.ID == "" || time.Now().After(e.Request.ExpiresAt) {
		return nil, ErrNotFound
	}

	key := openKey(e.Channel, e.Request.UserID, e.Request.Identifier)

	// Only the index entry still naming this request is cleared.
	if cur, err := s.open.Get(ctx, key); err == nil && cur == id {
		_ = s.open.Delete(ctx, key)
		_ = s.open.Sync(ctx)
	}

	return &e.Request, nil
}

// openKey indexes the open request of userID's address on channel.
func openKey(channel, userID, address string) string {
	return fmt.Sprintf("%s:%s:%x", channel, userID, sha256.Sum256([]byte(address)))
}
