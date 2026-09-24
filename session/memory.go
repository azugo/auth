package session

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"azugo.io/core/paginator"
	"github.com/oklog/ulid/v2"
)

type memoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	entropy  ulid.MonotonicReader
}

// memoryStore also implements the optional Lister capability.
var _ Lister = (*memoryStore)(nil)

// NewMemoryStore creates an empty in-memory session Store.
//
// Warning: Use it only for development and/or testing.
func NewMemoryStore() Store {
	return &memoryStore{
		sessions: make(map[string]*Session),
		entropy:  newEntropy(),
	}
}

// Create a new session.
// If session ID is empty a new ULID is assigned.
func (m *memoryStore) Create(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s.ID == "" {
		id, err := newID(m.entropy)
		if err != nil {
			return err
		}

		s.ID = id
	}

	if !s.Valid() {
		return errors.New("session already expired")
	}

	cp := *s
	m.sessions[s.ID] = &cp

	return nil
}

// Get session by ID.
func (m *memoryStore) Get(_ context.Context, id string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}

	cp := *s

	return &cp, nil
}

// Update replaces the stored session.
func (m *memoryStore) Update(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[s.ID]; !ok {
		return ErrNotFound
	}

	cp := *s
	m.sessions[s.ID] = &cp

	return nil
}

// Touch updates session activity by updating LastSeen time.
func (m *memoryStore) Touch(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		return ErrNotFound
	}

	if !s.Active() {
		return ErrNotFound
	}

	s.LastSeen = time.Now()

	return nil
}

// Revoke session and invalidate it.
func (m *memoryStore) Revoke(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		return ErrNotFound
	}

	if s.RevokedAt == nil {
		now := time.Now()
		s.RevokedAt = &now
	}

	return nil
}

// List returns userID's sessions matching filter ordered by LastSeen descending.
func (m *memoryStore) List(_ context.Context, userID string, filter *Filter, page *paginator.Paginator) ([]*Session, *paginator.Paginator, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*Session, 0)

	for _, s := range m.sessions {
		if s.UserID != userID {
			continue
		}

		if filter != nil && filter.ActiveOnly && !s.Active() {
			continue
		}

		cp := *s
		sessions = append(sessions, &cp)
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].LastSeen.After(sessions[j].LastSeen)
	})

	total := len(sessions)

	if page == nil {
		return sessions, paginator.New(total, max(total, 1), 1), nil
	}

	pages := paginator.New(total, page.PageSize(), page.Current())

	offset := (pages.Current() - 1) * pages.PageSize()
	if offset >= total {
		return []*Session{}, pages, nil
	}

	return sessions[offset:min(offset+pages.PageSize(), total)], pages, nil
}
