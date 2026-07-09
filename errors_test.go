package auth

import (
	"errors"
	"fmt"
	"testing"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/core/http"
	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
)

func headers(e *OAuthError) map[string]string {
	out := make(map[string]string)
	for k, v := range e.ErrorHeaders() {
		out[k] = v
	}

	return out
}

// mustOAuth recovers the concrete *OAuthError from the error the constructors return.
func mustOAuth(t *testing.T, err error) *OAuthError {
	t.Helper()

	var oe *OAuthError
	qt.Assert(t, qt.IsTrue(errors.As(err, &oe)))

	return oe
}

func TestNewOAuthErrorFrom(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		code   ErrorCode
	}{
		{"invalid credentials", contract.ErrInvalidCredentials, http.StatusBadRequest, ErrCodeInvalidGrant},
		{"user not found", contract.ErrUserNotFound, http.StatusUnauthorized, ErrCodeInvalidToken},
		{"session not found", session.ErrNotFound, http.StatusUnauthorized, ErrCodeInvalidToken},
		{"invalid token", token.ErrInvalidToken, http.StatusUnauthorized, ErrCodeInvalidToken},
		{"unexpected token type", token.ErrUnexpectedTokenType, http.StatusUnauthorized, ErrCodeInvalidToken},
		{"client not found", client.ErrNotFound, http.StatusUnauthorized, ErrCodeInvalidClient},
		{"user exists", contract.ErrUserAlreadyExists, http.StatusConflict, ErrCodeInvalidRequest},
		{"unknown", errors.New("boom"), http.StatusInternalServerError, ErrCodeServerError},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Wrapped sentinels are matched via errors.Is.
			got := NewOAuthErrorFrom(fmt.Errorf("context: %w", c.err))
			qt.Assert(t, qt.IsNotNil(got))

			oe := mustOAuth(t, got)
			qt.Check(t, qt.Equals(oe.StatusCode(), c.status))
			qt.Check(t, qt.Equals(oe.Code, c.code))
			// The original error is wrapped for logging…
			qt.Check(t, qt.ErrorIs(got, c.err))
			// …but never leaked into the client-facing description.
			qt.Check(t, qt.Not(qt.StringContains(oe.SafeError(), "boom")))
			qt.Check(t, qt.Not(qt.StringContains(oe.SafeError(), "context")))
		})
	}
}

func TestNewOAuthErrorFromNil(t *testing.T) {
	qt.Check(t, qt.IsNil(NewOAuthErrorFrom(nil)))
}

func TestOAuthErrorBasics(t *testing.T) {
	e := mustOAuth(t, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "expired code"))

	qt.Check(t, qt.Equals(e.StatusCode(), http.StatusBadRequest))
	qt.Check(t, qt.Equals(e.Code, ErrCodeInvalidGrant))
	qt.Check(t, qt.Equals(e.SafeError(), "expired code"))
	qt.Check(t, qt.Equals(e.Error(), "invalid_grant: expired code"))
}

func TestOAuthErrorMarshalJSON(t *testing.T) {
	e := mustOAuth(t, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "missing code_challenge",
		OAuthErrorURI("https://errors.example/invalid_request")))

	body, ct, ok := e.MarshalError("application/json; charset=utf-8")
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(ct, http.ContentTypeJSON))

	var got map[string]string
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &got)))
	qt.Check(t, qt.Equals(got["error"], "invalid_request"))
	qt.Check(t, qt.Equals(got["error_description"], "missing code_challenge"))
	qt.Check(t, qt.Equals(got["error_uri"], "https://errors.example/invalid_request"))
}

func TestOAuthErrorMarshalNonJSONFallsThrough(t *testing.T) {
	e := mustOAuth(t, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidGrant, "nope"))

	_, _, ok := e.MarshalError(http.ContentTypeTextHTML)
	qt.Check(t, qt.IsFalse(ok))
}

func TestOAuthErrorWWWAuthenticateOn401(t *testing.T) {
	e := mustOAuth(t, NewOAuthAuthenticateError(ErrCodeInvalidToken, "token expired", "api", "read"))
	qt.Check(t, qt.Equals(e.StatusCode(), http.StatusUnauthorized))

	h := headers(e)
	got, present := h[http.HeaderWWWAuthenticate]
	qt.Assert(t, qt.IsTrue(present))
	qt.Check(t, qt.Equals(got,
		`Bearer realm="api", error="invalid_token", error_description="token expired", scope="read"`))
}

func TestOAuthErrorNoWWWAuthenticateOffUnauthorized(t *testing.T) {
	// Only 401 carries a Bearer challenge; a 403 must not.
	e := mustOAuth(t, NewOAuthError(http.StatusForbidden, ErrCodeAccessDenied, "denied"))

	qt.Check(t, qt.Equals(len(headers(e)), 0))
}
