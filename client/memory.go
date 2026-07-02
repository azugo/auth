package client

import (
	"context"
	"errors"
	"sync"
)

// ErrNotFound is returned by Registry.GetClient when no client matches the given ID.
var ErrNotFound = errors.New("client not found")

// MemoryRegistry is an in-memory Registry for development and tests. It stores clients by value,
// normalizing each on Add (e.g. defaulting an empty ResponseMode) so GetClient is a plain
// copy-return and callers never share the registry's state.
type MemoryRegistry struct {
	mu      sync.RWMutex
	clients map[string]Client
}

// NewMemoryRegistry creates a registry seeded with the given clients (keyed by ID).
func NewMemoryRegistry(clients ...*Client) *MemoryRegistry {
	r := &MemoryRegistry{
		clients: make(map[string]Client, len(clients)),
	}

	for _, c := range clients {
		r.Add(c)
	}

	return r
}

// Add registers (or replaces) a client. It stores a normalized copy, leaving the caller's *Client
// untouched.
func (r *MemoryRegistry) Add(c *Client) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cp := *c
	if cp.ResponseMode == "" {
		cp.ResponseMode = ResponseModeJSON
	}

	r.clients[c.ID] = cp
}

// GetClient returns registered client by client ID.
func (r *MemoryRegistry) GetClient(_ context.Context, clientID string) (*Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	c, ok := r.clients[clientID]
	if !ok {
		return nil, ErrNotFound
	}

	return &c, nil
}
