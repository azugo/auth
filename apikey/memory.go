package apikey

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"azugo.io/auth/contract"

	"azugo.io/core/paginator"
)

// clone copies k without sharing its strings, which may alias a request buffer, or its times.
func clone(k *Key) *Key {
	c := *k
	c.ID = strings.Clone(k.ID)
	c.UserID = strings.Clone(k.UserID)
	c.ClientID = strings.Clone(k.ClientID)
	c.Name = strings.Clone(k.Name)
	c.Scope = strings.Clone(k.Scope)
	c.Hash = slices.Clone(k.Hash)
	c.ExpiresAt = cloneTime(k.ExpiresAt)
	c.RevokedAt = cloneTime(k.RevokedAt)
	c.RotatedAt = cloneTime(k.RotatedAt)

	if k.Subject != nil {
		c.Subject = &contract.AuthorizationDetail{
			Type:       strings.Clone(k.Subject.Type),
			Identifier: strings.Clone(k.Subject.Identifier),
			Actions:    cloneStrings(k.Subject.Actions),
		}
	}

	return &c
}

func cloneStrings(ss []string) []string {
	if ss == nil {
		return nil
	}

	c := make([]string, len(ss))
	for i, s := range ss {
		c[i] = strings.Clone(s)
	}

	return c
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}

	c := *t

	return &c
}

type memoryStore struct {
	mu   sync.RWMutex
	keys map[string]*Key
}

// NewMemoryStore creates an empty in-memory Store.
//
// Warning: Use it only for development and/or testing.
func NewMemoryStore() Store {
	return &memoryStore{keys: make(map[string]*Key)}
}

// Get returns the key by ID.
func (m *memoryStore) Get(_ context.Context, id string) (*Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k, ok := m.keys[id]
	if !ok {
		return nil, ErrNotFound
	}

	return clone(k), nil
}

// Create persists a new key.
func (m *memoryStore) Create(_ context.Context, k *Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if k.ID == "" {
		return errors.New("api key ID is required")
	}

	if _, ok := m.keys[k.ID]; ok {
		return errors.New("api key already exists")
	}

	if k.Subject != nil {
		for _, cur := range m.keys {
			if cur.ActsFor(k.Subject.Type, k.Subject.Identifier) && cur.RevokedAt == nil {
				return fmt.Errorf("%w: subject %s:%s already has a key", ErrInvalidKey, k.Subject.Type, k.Subject.Identifier)
			}
		}
	}

	cp := clone(k)
	m.keys[cp.ID] = cp

	return nil
}

// GetBySubject returns the unrevoked key of the object of type named by identifier.
func (m *memoryStore) GetBySubject(_ context.Context, typ, identifier string) (*Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, k := range m.keys {
		if k.ActsFor(typ, identifier) && k.RevokedAt == nil {
			return clone(k), nil
		}
	}

	return nil, ErrNotFound
}

// Revoke marks the key as revoked.
func (m *memoryStore) Revoke(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k, ok := m.keys[id]
	if !ok || k.RevokedAt != nil {
		return ErrNotFound
	}

	now := time.Now()
	k.RevokedAt = &now

	return nil
}

// RevokeAll revokes every valid key of userID and returns their IDs.
func (m *memoryStore) RevokeAll(_ context.Context, userID string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	revoked := make([]string, 0)

	for _, k := range m.keys {
		if k.UserID != userID || !k.Valid() {
			continue
		}

		at := now
		k.RevokedAt = &at
		revoked = append(revoked, k.ID)
	}

	return revoked, nil
}

// Rotate replaces the key's Hash and sets RotatedAt to at.
func (m *memoryStore) Rotate(_ context.Context, id string, hash []byte, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k, ok := m.keys[id]
	if !ok || k.RevokedAt != nil {
		return ErrNotFound
	}

	k.Hash = slices.Clone(hash)
	k.RotatedAt = &at

	return nil
}

// List returns userID's keys matching filter ordered by CreatedAt descending.
func (m *memoryStore) List(_ context.Context, userID string, filter *Filter, page *paginator.Paginator) ([]*Key, *paginator.Paginator, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]*Key, 0)

	for _, k := range m.keys {
		if k.UserID != userID {
			continue
		}

		if filter != nil && filter.ActiveOnly && !k.Valid() {
			continue
		}

		keys = append(keys, clone(k))
	}

	slices.SortFunc(keys, func(x, y *Key) int {
		return cmp.Or(y.CreatedAt.Compare(x.CreatedAt), strings.Compare(x.ID, y.ID))
	})

	total := len(keys)

	if page == nil {
		return keys, paginator.New(total, max(total, 1), 1), nil
	}

	pages := paginator.New(total, page.PageSize(), page.Current())

	offset := (pages.Current() - 1) * pages.PageSize()
	if offset >= total {
		return []*Key{}, pages, nil
	}

	return keys[offset:min(offset+pages.PageSize(), total)], pages, nil
}
