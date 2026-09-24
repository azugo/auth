package auth

import (
	"iter"
	"slices"
	"strings"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"
)

// OIDC scope values.
const (
	ScopeOpenID        = contract.ScopeOpenID
	ScopeProfile       = contract.ScopeProfile
	ScopeEmail         = contract.ScopeEmail
	ScopeAddress       = contract.ScopeAddress
	ScopePhone         = contract.ScopePhone
	ScopeOfflineAccess = contract.ScopeOfflineAccess
)

// scopeContains reports whether value is one of scope's space-separated fields.
func scopeContains(scope, value string) bool {
	for scope != "" {
		tok, rest, found := strings.Cut(scope, " ")
		if tok == value {
			return true
		}

		if !found {
			return false
		}

		scope = rest
	}

	return false
}

// grantedScope intersects the requested scope with the available scope.
func grantedScope(requested, available string) (string, bool) {
	if requested == "" {
		return available, true
	}

	for v := range strings.FieldsSeq(requested) {
		if !scopeContains(available, v) {
			return "", false
		}
	}

	return requested, true
}

// clientScope narrows scope to the client's registered Scopes; a client without any keeps scope.
func clientScope(cl *client.Client, scope string) string {
	if len(cl.Scopes) == 0 {
		return scope
	}

	return allowedScope(scope, slices.Values(cl.Scopes))
}

// allowedScope returns the allowed values that scope contains.
func allowedScope(scope string, allowed iter.Seq[string]) string {
	var b strings.Builder

	for v := range allowed {
		if !scopeContains(scope, v) {
			continue
		}

		if b.Len() > 0 {
			b.WriteByte(' ')
		}

		b.WriteString(v)
	}

	return b.String()
}
