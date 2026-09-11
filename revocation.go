package auth

import (
	"cmp"
	"context"
	"errors"
	"strings"
	"time"

	"azugo.io/auth/client"
	"azugo.io/auth/event"
	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/core/http"
)

// pasetoPrefix identifies the opaque PASETO tokens this library issues; anything else
// presented at /revoke or /introspect is treated as a JWT.
const pasetoPrefix = "v4.local."

// RevokeTokenRequest carries an RFC 7009 revocation request. The token_type_hint parameter
// is ignored.
type RevokeTokenRequest struct {
	Credentials   ClientCredentials
	Token         string
	BaseURL       string
	MountPath     string
	TokenEndpoint string
	IP            string
}

// RevokeToken implements RFC 7009: an opaque token revokes its session and JTI when it
// belongs to the calling client.
func (a *Auth) RevokeToken(ctx context.Context, in RevokeTokenRequest) error {
	cl, err := a.AuthenticateClient(ctx, in.Credentials, in.BaseURL, in.MountPath, in.TokenEndpoint)
	if err != nil {
		return err
	}

	if in.Token == "" {
		return nil
	}

	if strings.HasPrefix(in.Token, pasetoPrefix) {
		claims, err := a.codec.DecodeAccess(in.Token)
		if err != nil {
			// invalid token does not produce error
			return nil //nolint:nilerr
		}

		sess, err := a.sessions.Get(ctx, claims.SessionID)

		switch {
		case errors.Is(err, session.ErrNotFound), err == nil && cmp.Or(claims.ClientID, sess.ClientID) != cl.ID:
			// unknown or foreign token does not produce error
			return nil
		case err != nil:
			return NewOAuthErrorFrom(err)
		}

		if err := a.Transaction.Run(ctx, func(ctx context.Context) error {
			if err := a.sessions.Revoke(ctx, sess.ID); err != nil && !errors.Is(err, session.ErrNotFound) {
				return err
			}

			return a.jti.Revoke(ctx, claims.TokenID)
		}); err != nil {
			return NewOAuthErrorFrom(err)
		}

		a.emit(ctx, event.Event{Type: event.TypeTokenRevoked, UserID: sess.UserID, ClientID: cl.ID, IP: in.IP})

		return nil
	}

	if a.keys == nil {
		return nil
	}

	set, err := a.keys.KeySet(ctx)
	if err != nil {
		return NewOAuthErrorFrom(err)
	}

	claims, err := token.VerifyAccessToken(set, in.Token)
	if err != nil || claims.ClientID != cl.ID {
		// invalid or foreign token does not produce error
		return nil //nolint:nilerr
	}

	if err := a.denied.Deny(ctx, claims.TokenID, time.Until(time.Unix(claims.ExpiresAt, 0))); err != nil {
		return NewOAuthErrorFrom(err)
	}

	a.emit(ctx, event.Event{Type: event.TypeTokenRevoked, UserID: claims.Subject, ClientID: cl.ID, IP: in.IP})

	return nil
}

// IntrospectRequest carries an RFC 7662 introspection request. The token_type_hint parameter
// is ignored.
type IntrospectRequest struct {
	Credentials   ClientCredentials
	Token         string
	BaseURL       string
	MountPath     string
	TokenEndpoint string
}

// IntrospectionResponse is the RFC 7662 introspection response.
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	SessionID string `json:"sid,omitempty"`
}

// Introspect implements RFC 7662 for confidential clients: opaque PASETO tokens are validated
// through the in-process issuer path, JWT access tokens by signature + deny-list.
func (a *Auth) Introspect(ctx context.Context, in IntrospectRequest) (IntrospectionResponse, error) {
	cl, err := a.AuthenticateClient(ctx, in.Credentials, in.BaseURL, in.MountPath, in.TokenEndpoint)
	if err != nil {
		return IntrospectionResponse{}, err
	}

	if cl.Public || cl.TokenEndpointAuthMethod == client.TokenEndpointAuthNone || cl.TokenEndpointAuthMethod == "" {
		return IntrospectionResponse{}, NewOAuthError(http.StatusUnauthorized, ErrCodeInvalidClient, "introspection requires a confidential client")
	}

	if strings.HasPrefix(in.Token, pasetoPrefix) {
		claims, err := a.codec.DecodeAccess(in.Token)
		if err != nil {
			// invalid token does not produce error
			return IntrospectionResponse{}, nil //nolint:nilerr
		}

		info, sess, err := a.IntrospectToken(ctx, in.Token)
		if err != nil {
			var oe *OAuthError
			if errors.As(err, &oe) && oe.Code == ErrCodeServerError {
				return IntrospectionResponse{}, err
			}

			return IntrospectionResponse{}, nil
		}

		return IntrospectionResponse{
			Active:    true,
			Scope:     cmp.Or(claims.Scope, sess.Scope),
			ClientID:  cmp.Or(claims.ClientID, sess.ClientID),
			Username:  info.Name,
			TokenType: tokenTypeBearer,
			Subject:   sess.UserID,
			Audience:  cmp.Or(claims.ClientID, sess.ClientID),
			Issuer:    a.Issuer.URL(in.BaseURL, in.MountPath),
			ExpiresAt: claims.ExpiresAt,
			IssuedAt:  claims.IssuedAt,
			SessionID: sess.ID,
		}, nil
	}

	if a.keys == nil {
		return IntrospectionResponse{}, nil
	}

	set, err := a.keys.KeySet(ctx)
	if err != nil {
		return IntrospectionResponse{}, NewOAuthErrorFrom(err)
	}

	claims, err := token.VerifyAccessToken(set, in.Token)
	if err != nil {
		// invalid token does not produce error
		return IntrospectionResponse{}, nil //nolint:nilerr
	}

	denied, err := a.denied.Denied(ctx, claims.TokenID)
	if err != nil {
		return IntrospectionResponse{}, NewOAuthErrorFrom(err)
	}

	if denied {
		return IntrospectionResponse{}, nil
	}

	return IntrospectionResponse{
		Active:    true,
		Scope:     claims.Scope,
		ClientID:  claims.ClientID,
		TokenType: tokenTypeBearer,
		Subject:   claims.Subject,
		Audience:  claims.ClientID,
		Issuer:    claims.Issuer,
		ExpiresAt: claims.ExpiresAt,
		IssuedAt:  claims.IssuedAt,
	}, nil
}

// ValidateJWTAccessToken verifies a signed JWT bearer token (signature, expiry, deny-list)
// and resolves its subject through the UserProvider.
func (a *Auth) ValidateJWTAccessToken(ctx context.Context, tok string) (UserInfo, error) {
	if a.keys == nil {
		return UserInfo{}, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	set, err := a.keys.KeySet(ctx)
	if err != nil {
		return UserInfo{}, NewOAuthErrorFrom(err)
	}

	claims, err := token.VerifyAccessToken(set, tok)
	if err != nil {
		return UserInfo{}, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	if denied, err := a.denied.Denied(ctx, claims.TokenID); err != nil || denied {
		return UserInfo{}, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	info, err := a.users.GetUser(ctx, claims.Subject)
	if err != nil {
		return UserInfo{}, NewOAuthErrorFrom(err)
	}

	info.Scope = claims.Scope

	return info, nil
}
