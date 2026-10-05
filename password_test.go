package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestDefaultPasswordPolicy(t *testing.T) {
	cfg := &PasswordConfig{MinLength: 8, MaxLength: 16}
	p := NewPasswordPolicy(cfg)

	owner := UserInfo{ID: "u1", Email: "alice.smith@example.com", Name: "Alice Smith", Claims: map[string]any{"preferred_username": "alice"}}

	for _, tc := range []struct {
		name, password string
		weak           bool
	}{
		{"accepted", "correct horse", false},
		{"too short", "short1", true},
		{"too long", "far too long password", true},
		{"contains username", "xxALICExx", true},
		{"contains email local part", "alice.smith1", true},
		{"contains name", "Alice Smith!", true},
		{"short identifiers ignored", "bobbobbob", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := p.Validate(context.Background(), tc.password, owner)
			qt.Check(t, qt.Equals(errors.Is(err, ErrWeakPassword), tc.weak), qt.Commentf("%v", err))
		})
	}

	// Short owner identifiers are not matched.
	qt.Check(t, qt.IsNil(p.Validate(context.Background(), "bobbobbob", UserInfo{Email: "bob@x.io", Claims: map[string]any{"preferred_username": "bob"}})))

	// Limits are read live.
	cfg.MinLength = 14
	qt.Check(t, qt.IsTrue(errors.Is(p.Validate(context.Background(), "correct horse", owner), ErrWeakPassword)))
}

func TestWeakPasswordMapsToInvalidRequestWithReason(t *testing.T) {
	err := NewOAuthErrorFrom(NewPasswordPolicy(&PasswordConfig{MinLength: 8}).Validate(context.Background(), "short", UserInfo{}))

	var oe *OAuthError
	qt.Assert(t, qt.IsTrue(errors.As(err, &oe)))
	qt.Check(t, qt.Equals(oe.Code, ErrCodeInvalidRequest))
	qt.Check(t, qt.Equals(oe.StatusCode(), 400))
	qt.Check(t, qt.Equals(oe.Description, "password does not meet the policy: must be at least 8 characters"))
}
