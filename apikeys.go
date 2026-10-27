package auth

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

	"azugo.io/auth/apikey"
	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/event"
	"azugo.io/auth/token"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"azugo.io/core/paginator"
	"github.com/goccy/go-json"
)

// CreateAPIKeyRequest carries the caller's token and the new key's attributes.
type CreateAPIKeyRequest struct {
	Token string
	Name  string
	// Scope is the space-separated scope to limit the key to; empty = the caller's scope.
	Scope string
	// ExpiresAt is nil for a key that never expires.
	ExpiresAt *time.Time
	IP        string
}

// SubjectAPIKeyRequest describes a key acting for an object, such as deployment 12345, through a
// client, with the actions allowed on it.
type SubjectAPIKeyRequest struct {
	// Type and Identifier name the object, Actions what the key may do with it (RFC 9396).
	Type       string
	Identifier string
	Actions    []string
	ClientID   string
	// Name is the human-readable label; empty = type:identifier.
	Name string
	// ExpiresAt is nil for a key that never expires.
	ExpiresAt *time.Time
	IP        string
}

// APIKeyRequest carries the caller's token and the key to rotate or revoke.
type APIKeyRequest struct {
	Token string
	ID    string
	IP    string
}

// APIKeyResult is returned by CreateAPIKey and RotateAPIKey.
type APIKeyResult struct {
	Key *apikey.Key
	// Token is the API key token, returned only at creation and rotation.
	Token string
}

// apiKeysEnabled refuses the API key operations when no API key store is configured.
func (a *Auth) apiKeysEnabled() error {
	if a.apiKeys == nil {
		return NewOAuthError(http.StatusNotFound, ErrCodeInvalidRequest, "api keys are not enabled")
	}

	return nil
}

// CreateAPIKey creates an API key owned by the caller, limited to the scope of the caller's
// credential.
func (a *Auth) CreateAPIKey(ctx context.Context, in CreateAPIKeyRequest) (APIKeyResult, error) {
	if err := a.apiKeysEnabled(); err != nil {
		return APIKeyResult{}, err
	}

	info, err := a.RequireStepUp(ctx, in.Token, ActionCreateAPIKey)
	if err != nil {
		return APIKeyResult{}, err
	}

	scope, ok := grantedScope(in.Scope, info.Scope)
	if !ok {
		return APIKeyResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidScope, "requested scope exceeds the caller's scope")
	}

	return a.issueAPIKey(ctx, &apikey.Key{UserID: info.ID, ClientID: info.ClientID, Name: in.Name, Scope: scope, ExpiresAt: in.ExpiresAt}, in.IP)
}

// SubjectAPIKey returns the unrevoked key of the object of type named by identifier. The caller is
// trusted code: no credential is checked.
func (a *Auth) SubjectAPIKey(ctx context.Context, typ, identifier string) (*apikey.Key, error) {
	if err := a.apiKeysEnabled(); err != nil {
		return nil, err
	}

	key, err := a.apiKeys.GetBySubject(ctx, typ, identifier)
	if err != nil {
		return nil, NewOAuthErrorFrom(err)
	}

	return key, nil
}

// IssueSubjectAPIKey creates the key of an object acting through a client; an object with an
// unrevoked key is refused.
func (a *Auth) IssueSubjectAPIKey(ctx context.Context, in SubjectAPIKeyRequest) (APIKeyResult, error) {
	if err := a.apiKeysEnabled(); err != nil {
		return APIKeyResult{}, err
	}

	typ := strings.TrimSpace(in.Type)
	identifier := strings.TrimSpace(in.Identifier)

	if typ == "" || identifier == "" {
		return APIKeyResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "type and identifier are required")
	}

	cl, err := a.clients.GetClient(ctx, in.ClientID)
	if errors.Is(err, client.ErrNotFound) {
		return APIKeyResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "unknown client")
	}

	if err != nil {
		return APIKeyResult{}, NewOAuthErrorFrom(err)
	}

	if _, err := a.apiKeys.GetBySubject(ctx, typ, identifier); err == nil {
		return APIKeyResult{}, NewOAuthError(http.StatusConflict, ErrCodeInvalidRequest, "subject already has an api key")
	} else if !errors.Is(err, apikey.ErrNotFound) {
		return APIKeyResult{}, NewOAuthErrorFrom(err)
	}

	actions := make([]string, 0, len(in.Actions))

	for _, action := range in.Actions {
		if action = strings.TrimSpace(action); action != "" {
			actions = append(actions, action)
		}
	}

	slices.Sort(actions)
	actions = slices.Compact(actions)

	return a.issueAPIKey(ctx, &apikey.Key{
		Subject: &contract.AuthorizationDetail{
			Type:       typ,
			Identifier: identifier,
			Actions:    actions,
		},
		ClientID:  cl.ID,
		Name:      cmp.Or(in.Name, typ+":"+identifier),
		ExpiresAt: in.ExpiresAt,
	}, in.IP)
}

// RotateSubjectAPIKey replaces the token of the key of the object of type named by identifier; the
// previous token stops working at once.
func (a *Auth) RotateSubjectAPIKey(ctx context.Context, typ, identifier, ip string) (APIKeyResult, error) {
	key, err := a.SubjectAPIKey(ctx, typ, identifier)
	if err != nil {
		return APIKeyResult{}, err
	}

	now := time.Now()

	tok, hash, err := a.issueAPIKeyToken(key.ID)
	if err != nil {
		return APIKeyResult{}, err
	}

	if err := a.apiKeys.Rotate(ctx, key.ID, hash, now); err != nil {
		return APIKeyResult{}, NewOAuthErrorFrom(err)
	}

	key.Hash = hash
	key.RotatedAt = &now

	a.emit(ctx, event.Event{Type: event.TypeAPIKeyRotated, ClientID: key.ClientID, IP: ip, Detail: map[string]any{"key_id": key.ID, "subject": key.Subject}})

	return APIKeyResult{Key: key, Token: tok}, nil
}

// RevokeSubjectAPIKey revokes the key of the object of type named by identifier; an object without
// one is left as is.
func (a *Auth) RevokeSubjectAPIKey(ctx context.Context, typ, identifier, ip string) error {
	key, err := a.SubjectAPIKey(ctx, typ, identifier)
	if errors.Is(err, apikey.ErrNotFound) {
		return nil
	}

	if err != nil {
		return err
	}

	err = a.apiKeys.Revoke(ctx, key.ID)
	if errors.Is(err, apikey.ErrNotFound) {
		// A concurrent revoke already did it.
		return nil
	}

	if err != nil {
		return NewOAuthErrorFrom(err)
	}

	a.emit(ctx, event.Event{Type: event.TypeAPIKeyRevoked, ClientID: key.ClientID, IP: ip, Detail: map[string]any{"key_id": key.ID, "subject": key.Subject}})

	return nil
}

// AuthorizationDetails returns the RFC 9396 authorization details of a principal, which a subject
// API key carries for its object.
func AuthorizationDetails(u azugo.User) contract.AuthorizationDetails {
	var details contract.AuthorizationDetails

	for _, raw := range u.Claim(contract.ClaimAuthorizationDetails) {
		var d contract.AuthorizationDetail
		if err := json.Unmarshal([]byte(raw), &d); err == nil {
			details = append(details, d)
		}
	}

	return details
}

// issueAPIKey validates key's name and expiry, mints its ID and token, stores it and returns it
// with the token.
func (a *Auth) issueAPIKey(ctx context.Context, key *apikey.Key, ip string) (APIKeyResult, error) {
	key.Name = strings.TrimSpace(key.Name)
	if key.Name == "" {
		return APIKeyResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "name is required")
	}

	key.CreatedAt = time.Now()

	if key.ExpiresAt != nil && !key.ExpiresAt.After(key.CreatedAt) {
		return APIKeyResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "expires_at must be in the future")
	}

	id, err := newJTI()
	if err != nil {
		return APIKeyResult{}, NewOAuthErrorFrom(err)
	}

	tok, hash, err := a.issueAPIKeyToken(id)
	if err != nil {
		return APIKeyResult{}, err
	}

	key.ID = id
	key.Hash = hash

	if err := a.apiKeys.Create(ctx, key); err != nil {
		return APIKeyResult{}, NewOAuthErrorFrom(err)
	}

	a.emit(ctx, event.Event{Type: event.TypeAPIKeyCreated, UserID: key.UserID, ClientID: key.ClientID, IP: ip, Detail: map[string]any{"key_id": id, "name": key.Name, "scope": key.Scope, "subject": key.Subject}})

	return APIKeyResult{Key: key, Token: tok}, nil
}

// RotateAPIKey replaces the token of one of the caller's valid API keys; the previous token
// stops working at once.
func (a *Auth) RotateAPIKey(ctx context.Context, in APIKeyRequest) (APIKeyResult, error) {
	info, key, err := a.ownedAPIKey(ctx, in, ActionRotateAPIKey)
	if err != nil {
		return APIKeyResult{}, err
	}

	if !key.Valid() {
		return APIKeyResult{}, NewOAuthError(http.StatusBadRequest, ErrCodeInvalidRequest, "api key is revoked or expired")
	}

	now := time.Now()

	tok, hash, err := a.issueAPIKeyToken(key.ID)
	if err != nil {
		return APIKeyResult{}, err
	}

	if err := a.apiKeys.Rotate(ctx, key.ID, hash, now); err != nil {
		return APIKeyResult{}, NewOAuthErrorFrom(err)
	}

	key.Hash = hash
	key.RotatedAt = &now

	a.emit(ctx, event.Event{Type: event.TypeAPIKeyRotated, UserID: info.ID, ClientID: info.ClientID, IP: in.IP, Detail: map[string]any{"key_id": key.ID}})

	return APIKeyResult{Key: key, Token: tok}, nil
}

// issueAPIKeyToken mints a token for key id with a fresh random secret and returns it with the
// secret's hash.
func (a *Auth) issueAPIKeyToken(id string) (string, []byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", nil, NewOAuthErrorFrom(err)
	}

	sec := base64.RawURLEncoding.EncodeToString(secret)

	tok, err := a.codec.Encrypt(token.APIKeyClaims{
		Type:   token.TypeAPIKey,
		KeyID:  id,
		Secret: sec,
	})
	if err != nil {
		return "", nil, NewOAuthErrorFrom(err)
	}

	return tok, apikey.HashSecret(sec), nil
}

// ListAPIKeys returns the caller's API keys, ordered by CreatedAt descending.
func (a *Auth) ListAPIKeys(ctx context.Context, tok string, filter *apikey.Filter, page *paginator.Paginator) ([]*apikey.Key, *paginator.Paginator, error) {
	if err := a.apiKeysEnabled(); err != nil {
		return nil, nil, err
	}

	info, _, err := a.IntrospectFirstParty(ctx, tok)
	if err != nil {
		return nil, nil, err
	}

	keys, pages, err := a.apiKeys.List(ctx, info.ID, filter, page)
	if err != nil {
		return nil, nil, NewOAuthErrorFrom(err)
	}

	return keys, pages, nil
}

// RevokeAPIKey revokes one of the caller's API keys; an already revoked key is left as is.
func (a *Auth) RevokeAPIKey(ctx context.Context, in APIKeyRequest) error {
	info, key, err := a.ownedAPIKey(ctx, in, ActionRevokeAPIKey)
	if err != nil {
		return err
	}

	if key.RevokedAt != nil {
		return nil
	}

	err = a.apiKeys.Revoke(ctx, in.ID)
	if errors.Is(err, apikey.ErrNotFound) {
		// A concurrent revoke already did it.
		return nil
	}

	if err != nil {
		return NewOAuthErrorFrom(err)
	}

	a.emit(ctx, event.Event{Type: event.TypeAPIKeyRevoked, UserID: info.ID, ClientID: info.ClientID, IP: in.IP, Detail: map[string]any{"key_id": key.ID}})

	return nil
}

// ownedAPIKey resolves the caller of in under the step-up policy for action and the key in names,
// which must be theirs; another user's key is not found.
func (a *Auth) ownedAPIKey(ctx context.Context, in APIKeyRequest, action string) (UserInfo, *apikey.Key, error) {
	if err := a.apiKeysEnabled(); err != nil {
		return UserInfo{}, nil, err
	}

	info, err := a.RequireStepUp(ctx, in.Token, action)
	if err != nil {
		return UserInfo{}, nil, err
	}

	key, err := a.apiKeys.Get(ctx, in.ID)
	if err != nil {
		return UserInfo{}, nil, NewOAuthErrorFrom(err)
	}

	if key.UserID != info.ID {
		return UserInfo{}, nil, NewOAuthErrorFrom(apikey.ErrNotFound)
	}

	return info, key, nil
}

// ValidateAPIKey validates an API key token against the stored hash of its secret and returns
// its owner, limited to the scope the key and the owner both hold.
func (a *Auth) ValidateAPIKey(ctx context.Context, tok string) (UserInfo, *apikey.Key, error) {
	if tok == "" {
		return UserInfo{}, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	claims, err := a.codec.DecodeAPIKey(tok)
	if err != nil {
		return UserInfo{}, nil, NewOAuthErrorFrom(err)
	}

	return a.validateAPIKey(ctx, claims)
}

// IntrospectWithAPIKey validates an access token, session-cookie token or API key token,
// decrypting it once, and returns the resolved user.
func (a *Auth) IntrospectWithAPIKey(ctx context.Context, tok string) (UserInfo, error) {
	if tok == "" {
		return UserInfo{}, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	access, key, err := a.codec.Decode(tok)
	if err != nil {
		return UserInfo{}, NewOAuthErrorFrom(err)
	}

	if key != nil {
		info, _, err := a.validateAPIKey(ctx, key)

		return info, err
	}

	info, _, _, err := a.introspectClaims(ctx, access)

	return info, err
}

// validateAPIKey resolves the valid key and its owner behind decoded API key claims.
func (a *Auth) validateAPIKey(ctx context.Context, claims *token.APIKeyClaims) (UserInfo, *apikey.Key, error) {
	if a.apiKeys == nil {
		return UserInfo{}, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	key, err := a.apiKeys.Get(ctx, claims.KeyID)
	if errors.Is(err, apikey.ErrNotFound) {
		return UserInfo{}, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	if err != nil {
		return UserInfo{}, nil, NewOAuthErrorFrom(err)
	}

	if !key.Matches(claims.Secret) || !key.Valid() {
		return UserInfo{}, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	// The key acts for its client, which may since have been removed or narrowed.
	cl, err := a.clients.GetClient(ctx, key.ClientID)
	if errors.Is(err, client.ErrNotFound) {
		return UserInfo{}, nil, NewOAuthErrorFrom(token.ErrInvalidToken)
	}

	if err != nil {
		return UserInfo{}, nil, NewOAuthErrorFrom(err)
	}

	if key.Subject != nil {
		return UserInfo{AuthorizationDetails: contract.AuthorizationDetails{*key.Subject}, ClientID: key.ClientID}, key, nil
	}

	info, err := a.users.GetUser(ctx, key.UserID)
	if err != nil {
		return UserInfo{}, nil, NewOAuthErrorFrom(err)
	}

	info.Scope = clientScope(cl, allowedScope(info.Scope, strings.FieldsSeq(key.Scope)))
	info.ClientID = key.ClientID
	info.ACR = ""
	info.AMR = nil

	return info, key, nil
}
