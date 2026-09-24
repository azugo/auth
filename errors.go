package auth

import (
	"errors"
	"iter"
	"strconv"
	"strings"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/mfa"
	"azugo.io/auth/provider"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"github.com/goccy/go-json"
)

var (
	// ErrInvalidCredentials is returned for a bad username and/or password.
	ErrInvalidCredentials = contract.ErrInvalidCredentials
	// ErrUserAlreadyExists is returned when the account is taken.
	ErrUserAlreadyExists = contract.ErrUserAlreadyExists
	// ErrUserNotFound is returned when the user is unknown.
	ErrUserNotFound = contract.ErrUserNotFound
	// ErrUnsupportedGrantType is returned for grant_type this library does not
	// support.
	ErrUnsupportedGrantType = errors.New("unsupported grant type")
	// ErrLoginRequired is returned by Refresh when the presented session cookie is missing,
	// expired, or otherwise cannot be silently re-authenticated.
	ErrLoginRequired = errors.New("login required")
	// ErrUnmetAuthenticationRequirements is returned when an essential acr request or the
	// client's MinACR floor cannot be satisfied.
	ErrUnmetAuthenticationRequirements = errors.New("unmet authentication requirements")
	// ErrFirstPartyRequired is returned when an access token issued to another client is
	// presented where only the session's own credential is accepted.
	ErrFirstPartyRequired = errors.New("first-party credential required")
)

// ErrorCode is an RFC 6749 / RFC 6750 / RFC 9470 OAuth 2.0 error code.
type ErrorCode string

// OAuth error codes.
const (
	ErrCodeLoginRequired                   ErrorCode = "login_required"
	ErrCodeSessionRevoked                  ErrorCode = "session_revoked"
	ErrCodeInvalidRequest                  ErrorCode = "invalid_request"
	ErrCodeInvalidClient                   ErrorCode = "invalid_client"
	ErrCodeInvalidGrant                    ErrorCode = "invalid_grant"
	ErrCodeUnauthorizedClient              ErrorCode = "unauthorized_client"
	ErrCodeUnsupportedGrantType            ErrorCode = "unsupported_grant_type"
	ErrCodeAccessDenied                    ErrorCode = "access_denied"
	ErrCodeUnmetAuthenticationRequirements ErrorCode = "unmet_authentication_requirements"
	ErrCodeInvalidDPoPProof                ErrorCode = "invalid_dpop_proof"
	ErrCodeUseDPoPNonce                    ErrorCode = "use_dpop_nonce"
	ErrCodeInvalidToken                    ErrorCode = "invalid_token"
	ErrCodeInsufficientScope               ErrorCode = "insufficient_scope"
	ErrCodeServerError                     ErrorCode = "server_error"
	ErrCodeUnsupportedResponseType         ErrorCode = "unsupported_response_type"
	ErrCodeInvalidScope                    ErrorCode = "invalid_scope"
	ErrCodeSlowDown                        ErrorCode = "slow_down"
)

var (
	_ http.ResponseStatusCode = (*OAuthError)(nil)
	_ azugo.SafeError         = (*OAuthError)(nil)
	_ azugo.ErrorHeaders      = (*OAuthError)(nil)
	_ azugo.ErrorMarshaler    = (*OAuthError)(nil)
)

// OAuthError represents an OAuth 2.0 error response.
type OAuthError struct {
	// Code is the RFC 6749 error code (e.g. "invalid_token", "insufficient_scope").
	Code ErrorCode
	// Description is the human-readable error_description.
	Description string
	// RetryAfter, when non-zero, is surfaced as a Retry-After header (throttled requests).
	RetryAfter time.Duration

	uri    string // optional error_uri
	realm  string
	scope  string
	status int
	cause  error // underlying error
}

// OAuthErrorOption customizes an OAuthError at construction.
type OAuthErrorOption func(*OAuthError)

// OAuthErrorURI sets the optional error_uri pointing to error documentation.
func OAuthErrorURI(uri string) OAuthErrorOption {
	return func(e *OAuthError) {
		e.uri = uri
	}
}

// Unwrap exposes the wrapped cause (set by NewOAuthErrorFrom) so the server can log/inspect the
// original error with errors.Is/As.
func (e *OAuthError) Unwrap() error {
	return e.cause
}

// NewOAuthError creates an OAuthError with the given HTTP status, error code and description.
// Optional attributes (e.g. OAuthErrorURI option).
func NewOAuthError(status int, code ErrorCode, description string, opts ...OAuthErrorOption) error {
	e := &OAuthError{
		Code:        code,
		Description: description,
		status:      status,
	}

	for _, opt := range opts {
		opt(e)
	}

	return e
}

// NewThrottledError creates a 429 Too Many Requests OAuthError carrying a Retry-After hint.
func NewThrottledError(retryAfter time.Duration) error {
	return &OAuthError{
		Code:        ErrCodeSlowDown,
		Description: "too many attempts",
		RetryAfter:  retryAfter,
		status:      http.StatusTooManyRequests,
	}
}

// NewOAuthAuthenticateError creates a 401 Unauthorized OAuthError that emits an RFC 6750
// WWW-Authenticate: Bearer challenge.
func NewOAuthAuthenticateError(code ErrorCode, description, realm, scope string, opts ...OAuthErrorOption) error {
	e := &OAuthError{
		Code:        code,
		Description: description,
		realm:       realm,
		scope:       scope,
		status:      http.StatusUnauthorized,
	}

	for _, opt := range opts {
		opt(e)
	}

	return e
}

// NewOAuthErrorFrom maps a authentication specifc errors to OAuth 2.0 error and status code.
func NewOAuthErrorFrom(err error) error {
	var oe *OAuthError

	switch {
	case err == nil:
		return nil
	case errors.As(err, &oe):
		// Already mapped - pass through unchanged.
		return err
	case errors.Is(err, contract.ErrInvalidCredentials):
		// Invalid username and/or password.
		return newOAuthErrorWrapped(http.StatusBadRequest, ErrCodeInvalidGrant, "invalid credentials", err)
	case errors.Is(err, contract.ErrUserNotFound), errors.Is(err, session.ErrNotFound),
		errors.Is(err, token.ErrInvalidToken), errors.Is(err, token.ErrUnexpectedTokenType):
		// Bad or expired token.
		return newOAuthErrorWrapped(http.StatusUnauthorized, ErrCodeInvalidToken, "invalid token", err)
	case errors.Is(err, client.ErrNotFound):
		// Unknown/invalid client or it's parameters.
		return newOAuthErrorWrapped(http.StatusUnauthorized, ErrCodeInvalidClient, "invalid client", err)
	case errors.Is(err, contract.ErrUserAlreadyExists):
		// Account registration conflict.
		return newOAuthErrorWrapped(http.StatusConflict, ErrCodeInvalidRequest, "account already exists", err)
	case errors.Is(err, provider.ErrNotFound):
		return newOAuthErrorWrapped(http.StatusNotFound, ErrCodeInvalidRequest, "unknown provider", err)
	case errors.Is(err, provider.ErrLinkNotFound):
		return newOAuthErrorWrapped(http.StatusNotFound, ErrCodeInvalidRequest, "identity link not found", err)
	case errors.Is(err, provider.ErrIdentityLinked):
		return newOAuthErrorWrapped(http.StatusConflict, ErrCodeInvalidRequest, "identity already linked to another user", err)
	case errors.Is(err, ErrUnsupportedGrantType):
		return newOAuthErrorWrapped(http.StatusBadRequest, ErrCodeUnsupportedGrantType, "unsupported grant type", err)
	case errors.Is(err, ErrLoginRequired):
		return newOAuthErrorWrapped(http.StatusUnauthorized, ErrCodeLoginRequired, "login required", err)
	case errors.Is(err, ErrUnmetAuthenticationRequirements):
		return newOAuthErrorWrapped(http.StatusForbidden, ErrCodeUnmetAuthenticationRequirements, "authentication requirements not met", err)
	case errors.Is(err, ErrFirstPartyRequired):
		return newOAuthErrorWrapped(http.StatusForbidden, ErrCodeInsufficientScope, "first-party credential required", err)
	case errors.Is(err, mfa.ErrUnknownMethod):
		return newOAuthErrorWrapped(http.StatusNotFound, ErrCodeInvalidRequest, "unknown mfa method", err)
	case errors.Is(err, mfa.ErrNotEnrolled):
		return newOAuthErrorWrapped(http.StatusBadRequest, ErrCodeInvalidRequest, "mfa method not enrolled", err)
	case errors.Is(err, mfa.ErrInvalidResponse):
		return newOAuthErrorWrapped(http.StatusBadRequest, ErrCodeInvalidGrant, "invalid mfa response", err)
	default:
		return newOAuthErrorWrapped(http.StatusInternalServerError, ErrCodeServerError, "internal error", err)
	}
}

func newOAuthErrorWrapped(status int, code ErrorCode, description string, cause error) *OAuthError {
	return &OAuthError{
		Code:        code,
		Description: description,
		status:      status,
		cause:       cause,
	}
}

// Error string.
func (e *OAuthError) Error() string {
	if e.Description != "" {
		return string(e.Code) + ": " + e.Description
	}

	return string(e.Code)
}

// StatusCode to set for error response.
func (e *OAuthError) StatusCode() int {
	return e.status
}

// SafeError returns error description.
func (e *OAuthError) SafeError() string {
	return e.Description
}

// ErrorHeaders sets the WWW-Authenticate: Bearer header and, when throttled, Retry-After.
func (e *OAuthError) ErrorHeaders() iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		if e.RetryAfter > 0 {
			if !yield(http.HeaderRetryAfter, strconv.Itoa(int(e.RetryAfter.Seconds()+0.999))) {
				return
			}
		}

		if e.status != http.StatusUnauthorized {
			return
		}

		var b strings.Builder

		b.WriteString(tokenTypeBearer)

		if e.realm != "" {
			b.WriteString(` realm="`)
			b.WriteString(e.realm)
			b.WriteByte('"')
		}

		if e.Code != "" {
			b.WriteString(`, error="`)
			b.WriteString(string(e.Code))
			b.WriteByte('"')
		}

		if e.Description != "" {
			b.WriteString(`, error_description="`)
			b.WriteString(e.Description)
			b.WriteByte('"')
		}

		if e.uri != "" {
			b.WriteString(`, error_uri="`)
			b.WriteString(e.uri)
			b.WriteByte('"')
		}

		if e.scope != "" {
			b.WriteString(`, scope="`)
			b.WriteString(e.scope)
			b.WriteByte('"')
		}

		yield(http.HeaderWWWAuthenticate, b.String())
	}
}

// MarshalError renders the RFC 6749 JSON response.
func (e *OAuthError) MarshalError(contentType string) ([]byte, string, bool) {
	if !strings.HasPrefix(contentType, http.ContentTypeJSON) {
		return nil, "", false
	}

	type body struct {
		Error       string `json:"error"`
		Description string `json:"error_description,omitempty"`
		URI         string `json:"error_uri,omitempty"`
	}

	data, err := json.Marshal(body{
		Error:       string(e.Code),
		Description: e.Description,
		URI:         e.uri,
	})
	if err != nil {
		return nil, "", false
	}

	return data, http.ContentTypeJSON, true
}
