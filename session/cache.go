package session

import (
	"context"
	"errors"
	"time"

	"azugo.io/core/cache"
	"github.com/oklog/ulid/v2"
)

const cacheInstanceName = "auth.session"

type cacheStore struct {
	c       cache.Instance[Session]
	entropy ulid.MonotonicReader
}

// NewCacheStore creates a cache-backed session Store over the app's cache.
func NewCacheStore(c *cache.Cache) (Store, error) {
	inst, err := cache.Create[Session](c, cacheInstanceName)
	if err != nil {
		return nil, err
	}

	return &cacheStore{c: inst, entropy: newEntropy()}, nil
}

// Create and store new session.
// If session ID is empty a new ULID is assigned.
func (s *cacheStore) Create(ctx context.Context, sess *Session) error {
	if sess.ID == "" {
		id, err := newID(s.entropy)
		if err != nil {
			return err
		}

		sess.ID = id
	}

	if !sess.Valid() {
		return errors.New("session already expired")
	}

	return s.c.Set(ctx, sess.ID, *sess, cache.TTL[Session](time.Until(sess.ExpiresAt)))
}

// Get session by ID.
func (s *cacheStore) Get(ctx context.Context, id string) (*Session, error) {
	sess, err := s.c.Get(ctx, id)
	if err != nil {
		var knf cache.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil, ErrNotFound
		}

		return nil, err
	}

	if sess.ID == "" {
		return nil, ErrNotFound
	}

	return &sess, nil
}

// Touch updates session activity by updating LastSeen.
func (s *cacheStore) Touch(ctx context.Context, id string) error {
	sess, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	if !sess.Active() {
		return ErrNotFound
	}

	sess.LastSeen = time.Now()

	return s.c.Set(ctx, id, *sess, cache.TTL[Session](time.Until(sess.ExpiresAt)))
}

// Revoke session by deleting it.
func (s *cacheStore) Revoke(ctx context.Context, id string) error {
	if err := s.c.Delete(ctx, id); err != nil {
		var knf cache.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil
		}

		return err
	}

	return nil
}
