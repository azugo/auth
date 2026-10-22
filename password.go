package auth

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"azugo.io/auth/contract"
)

// NewPasswordPolicy returns the default policy: a length within config and no
// obvious reuse of the account's login name, email or name.
func NewPasswordPolicy(config *PasswordConfig) contract.PasswordPolicy {
	return lengthPolicy{Config: config}
}

type lengthPolicy struct {
	Config *PasswordConfig
}

// Validate password length based on configuration.
func (p lengthPolicy) Validate(_ context.Context, password string, info UserInfo) error {
	n := utf8.RuneCountInString(password)

	if n < p.Config.MinLength {
		return fmt.Errorf("%w: must be at least %d characters", ErrWeakPassword, p.Config.MinLength)
	}

	if p.Config.MaxLength > 0 && n > p.Config.MaxLength {
		return fmt.Errorf("%w: must be at most %d characters", ErrWeakPassword, p.Config.MaxLength)
	}

	username, _ := info.Claims["preferred_username"].(string)
	password = strings.ToLower(password)

	ids := []string{username, info.Name}

	for _, contacts := range info.Contacts {
		for _, c := range contacts {
			local, _, _ := strings.Cut(c.Address, "@")
			ids = append(ids, c.Address, local)
		}
	}

	// Check only values that are more than 3 chars
	if slices.ContainsFunc(ids, func(id string) bool {
		return utf8.RuneCountInString(id) > 3 && strings.Contains(password, strings.ToLower(id))
	}) {
		return fmt.Errorf("%w: must not contain your username, contact address or name", ErrWeakPassword)
	}

	return nil
}
