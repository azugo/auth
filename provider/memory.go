package provider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sort"
	"sync"
	"time"

	"azugo.io/core/paginator"
)

type memoryIdentityStore struct {
	mu    sync.RWMutex
	links map[string]*IdentityLink
}

// NewMemoryIdentityStore creates an empty in-memory IdentityStore.
//
// Warning: Use it only for development and/or testing.
func NewMemoryIdentityStore() IdentityStore {
	return &memoryIdentityStore{links: make(map[string]*IdentityLink)}
}

// Lookup resolves an external subject to its link.
func (m *memoryIdentityStore) Lookup(_ context.Context, provider, subject string) (*IdentityLink, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, l := range m.links {
		if l.Provider == provider && l.Subject == subject {
			cp := *l

			return &cp, nil
		}
	}

	return nil, ErrLinkNotFound
}

// Link binds a verified identity to a user.
func (m *memoryIdentityStore) Link(_ context.Context, l *IdentityLink) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, existing := range m.links {
		if existing.Provider != l.Provider || existing.Subject != l.Subject {
			continue
		}

		if existing.UserID != l.UserID {
			return ErrIdentityLinked
		}

		now := time.Now()
		existing.LastUsedAt = &now
		*l = *existing

		return nil
	}

	if l.ID == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return err
		}

		l.ID = base64.RawURLEncoding.EncodeToString(b)
	}

	if l.LinkedAt.IsZero() {
		l.LinkedAt = time.Now()
	}

	cp := *l
	m.links[l.ID] = &cp

	return nil
}

// List returns userID's links ordered by LinkedAt descending.
func (m *memoryIdentityStore) List(_ context.Context, userID, provider string, page *paginator.Paginator) ([]*IdentityLink, *paginator.Paginator, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	links := make([]*IdentityLink, 0)

	for _, l := range m.links {
		if l.UserID != userID || (provider != "" && l.Provider != provider) {
			continue
		}

		cp := *l
		links = append(links, &cp)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].LinkedAt.After(links[j].LinkedAt)
	})

	total := len(links)

	if page == nil {
		return links, paginator.New(total, max(total, 1), 1), nil
	}

	pages := paginator.New(total, page.PageSize(), page.Current())

	offset := (pages.Current() - 1) * pages.PageSize()
	if offset >= total {
		return []*IdentityLink{}, pages, nil
	}

	return links[offset:min(offset+pages.PageSize(), total)], pages, nil
}

// Unlink removes one caller-owned link.
func (m *memoryIdentityStore) Unlink(_ context.Context, userID, linkID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, ok := m.links[linkID]
	if !ok || l.UserID != userID {
		return ErrLinkNotFound
	}

	delete(m.links, linkID)

	return nil
}
