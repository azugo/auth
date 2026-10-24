// Package apikey defines the API key model and the Store interface that persists it.
package apikey

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"

	"azugo.io/core/paginator"
)

var (
	// ErrNotFound is returned when no key matches the given ID.
	ErrNotFound = errors.New("api key not found")
	// ErrInvalidKey is returned by Store.Create for a key it does not accept, e.g. a too long
	// name or too many keys for the user; wrap it to say why.
	ErrInvalidKey = errors.New("invalid api key")
)

// Key is one API key record.
type Key struct {
	// ID is the key ID carried in the API key token.
	ID     string
	UserID string
	// ClientID is the client of the session that created the key.
	ClientID string
	// Name is the human-readable label set at creation.
	Name string
	// Scope is the space-separated scope the key is limited to, narrowed to the owner's scope at
	// validation.
	Scope     string
	CreatedAt time.Time
	// ExpiresAt is nil when the key never expires.
	ExpiresAt *time.Time
	RevokedAt *time.Time
	// RotatedAt is when the key's token was last replaced; nil when never.
	RotatedAt *time.Time
	// Hash is the SHA-256 of the secret carried in the key's token.
	Hash []byte
}

// Valid returns true when the key is neither revoked nor expired.
func (k *Key) Valid() bool {
	return k.RevokedAt == nil && (k.ExpiresAt == nil || time.Now().Before(*k.ExpiresAt))
}

// Matches reports whether secret is the one the key was created with.
func (k *Key) Matches(secret string) bool {
	return len(k.Hash) == sha256.Size && subtle.ConstantTimeCompare(HashSecret(secret), k.Hash) == 1
}

// HashSecret returns the Key.Hash of a token secret.
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))

	return sum[:]
}

// Filter narrows which of a user's keys to return.
type Filter struct {
	// ActiveOnly returns only valid keys.
	ActiveOnly bool
}

// Store persists API key records by ID.
type Store interface {
	// Get returns the key by ID, revoked or expired ones included, or ErrNotFound if absent.
	Get(ctx context.Context, id string) (*Key, error)
	// Create persists a new key with its ID already set, or returns an error wrapping
	// ErrInvalidKey for a key it does not accept.
	Create(ctx context.Context, key *Key) error
	// Revoke marks the key as revoked, or returns ErrNotFound for a missing or already revoked key.
	Revoke(ctx context.Context, id string) error
	// RevokeAll revokes every valid key of userID and returns their IDs.
	RevokeAll(ctx context.Context, userID string) ([]string, error)
	// Rotate replaces the key's Hash and sets RotatedAt to at, leaving RevokedAt unchanged, or
	// returns ErrNotFound for a missing or revoked key.
	Rotate(ctx context.Context, id string, hash []byte, at time.Time) error
	// List returns userID's keys matching filter ordered by CreatedAt descending; a nil page
	// returns every matching key.
	List(ctx context.Context, userID string, filter *Filter, page *paginator.Paginator) (keys []*Key, pages *paginator.Paginator, err error)
}
