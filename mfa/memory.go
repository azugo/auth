package mfa

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"
)

type memoryStore struct {
	mu          sync.RWMutex
	enrollments map[string][]*Enrollment
}

// NewMemoryStore creates an empty in-memory Store.
//
// Warning: Use it only for development and/or testing.
func NewMemoryStore() Store {
	return &memoryStore{enrollments: make(map[string][]*Enrollment)}
}

func (m *memoryStore) index(userID, id string) int {
	return slices.IndexFunc(m.enrollments[userID], func(e *Enrollment) bool { return e.ID == id })
}

func clone(e *Enrollment) *Enrollment {
	c := *e
	c.Secret = slices.Clone(e.Secret)

	return &c
}

// List returns userID's enrollments, oldest first.
func (m *memoryStore) List(_ context.Context, userID string) ([]*Enrollment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*Enrollment, 0, len(m.enrollments[userID]))
	for _, e := range m.enrollments[userID] {
		out = append(out, clone(e))
	}

	return out, nil
}

// Enroll persists e under its ID, replacing an enrollment with the same ID.
func (m *memoryStore) Enroll(_ context.Context, e *Enrollment) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if i := m.index(e.UserID, e.ID); i >= 0 {
		m.enrollments[e.UserID][i] = clone(e)

		return nil
	}

	m.enrollments[e.UserID] = append(m.enrollments[e.UserID], clone(e))

	return nil
}

// CompareAndSwap atomically replaces an enrollment secret when it has not changed.
func (m *memoryStore) CompareAndSwap(_ context.Context, userID, id string, expected, replacement []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	i := m.index(userID, id)
	if i < 0 || !bytes.Equal(m.enrollments[userID][i].Secret, expected) {
		return false, nil
	}

	m.enrollments[userID][i].Secret = slices.Clone(replacement)

	return true, nil
}

// Touch records that userID's enrollment id was used at at.
func (m *memoryStore) Touch(_ context.Context, userID, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	i := m.index(userID, id)
	if i < 0 {
		return ErrNotEnrolled
	}

	m.enrollments[userID][i].LastUsedAt = &at

	return nil
}

// Revoke removes userID's enrollment id.
func (m *memoryStore) Revoke(_ context.Context, userID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	i := m.index(userID, id)
	if i < 0 {
		return ErrNotEnrolled
	}

	m.enrollments[userID] = slices.Delete(m.enrollments[userID], i, i+1)

	return nil
}
