package provider

import (
	"context"
	"errors"
	"time"

	"azugo.io/core/paginator"
)

var (
	// ErrIdentityLinked is returned when a (provider, subject) identity is already bound to a
	// different user and the relink policy refuses the move.
	ErrIdentityLinked = errors.New("external identity already linked to another user")
	// ErrLinkNotFound is returned when no identity link matches.
	ErrLinkNotFound = errors.New("identity link not found")
)

// IdentityLink is one external identity (an IdP account) linked to a local user. A user may
// link many, across providers.
type IdentityLink struct {
	ID       string
	UserID   string
	Provider string
	// Subject is the provider's stable subject (sub) for this identity.
	Subject    string
	Email      string
	LinkedAt   time.Time
	LastUsedAt *time.Time
}

// IdentityStore persists external-identity links, used both to resolve logins (Lookup) and to
// manage links. (provider, subject) is unique: an external identity maps to exactly one local
// user at all times.
type IdentityStore interface {
	// Lookup resolves an external subject to its link, or ErrLinkNotFound.
	Lookup(ctx context.Context, provider, subject string) (*IdentityLink, error)
	// Link binds a verified identity to a user, updating LastUsedAt when (provider, subject)
	// is already bound to the same user. It MUST return ErrIdentityLinked when bound to a
	// different user - the caller consults the RelinkAuthorizer BEFORE Link, so Link itself
	// only ever sees a conflict-free insert.
	Link(ctx context.Context, l *IdentityLink) error
	// List returns userID's links ordered by LinkedAt descending; provider == "" returns all.
	List(ctx context.Context, userID, provider string, page *paginator.Paginator) (links []*IdentityLink, pages *paginator.Paginator, err error)
	// Unlink removes one caller-owned link, or ErrLinkNotFound.
	Unlink(ctx context.Context, userID, linkID string) error
}

// RelinkAuthorizer decides whether an identity already linked to existing.UserID may be moved
// to newUserID. The default, when none is set, is to refuse - the conflict surfaces as
// ErrIdentityLinked.
type RelinkAuthorizer interface {
	AllowRelink(ctx context.Context, existing *IdentityLink, newUserID string) (bool, error)
}

// RelinkAuthorizerFunc adapts a plain function to RelinkAuthorizer.
type RelinkAuthorizerFunc func(ctx context.Context, existing *IdentityLink, newUserID string) (bool, error)

// AllowRelink implements RelinkAuthorizer.
func (f RelinkAuthorizerFunc) AllowRelink(ctx context.Context, existing *IdentityLink, newUserID string) (bool, error) {
	return f(ctx, existing, newUserID)
}
