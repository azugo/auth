// Package event defines the audit event sink for security-relevant auth events.
package event

import (
	"context"
	"time"
)

// Well-known event types.
const (
	TypeLoginSuccess   = "login.success"
	TypeLoginFailure   = "login.failure"
	TypeLockout        = "lockout"
	TypeTokenIssued    = "token.issued"
	TypeTokenRevoked   = "token.revoked"
	TypeSessionRevoked = "session.revoked"
)

// Event is one security-relevant occurrence for audit/SIEM.
type Event struct {
	Type     string
	UserID   string
	ClientID string
	IP       string
	At       time.Time
	Detail   map[string]any
}

// Sink receives security-relevant events. Implementations must be non-blocking or buffer
// internally; Emit is called inline on request paths.
type Sink interface {
	Emit(ctx context.Context, e Event)
}

// SinkFunc adapts a plain function to the Sink interface.
type SinkFunc func(ctx context.Context, e Event)

// Emit implements Sink.
func (f SinkFunc) Emit(ctx context.Context, e Event) {
	f(ctx, e)
}

// Discard returns a Sink that drops every event.
func Discard() Sink {
	return SinkFunc(func(context.Context, Event) {})
}
