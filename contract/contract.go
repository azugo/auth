// Package contract holds the cross-cutting types and interfaces shared between the
// base auth package and the plugin packages.
package contract

import (
	"context"
	"slices"

	"azugo.io/azugo/token"
	"azugo.io/azugo/user"
	"github.com/goccy/go-json"
)

// UserProvider loads user data.
type UserProvider interface {
	// GetUser returns the current state of a user by ID.
	GetUser(ctx context.Context, userID string) (UserInfo, error)
}

// PasswordAuthenticator is an optional UserProvider extension for local passwords; without it
// there is no password login, re-authentication, change, reset or registration.
type PasswordAuthenticator interface {
	// Authenticate returns the user behind username and password, or ErrInvalidCredentials. A
	// username that is a contact address matches only an account holding it verified, as on a
	// channel with contact verification several accounts may hold it unverified.
	Authenticate(ctx context.Context, username, password string) (UserInfo, error)
	// VerifyPassword returns ErrInvalidCredentials when password is not user's.
	VerifyPassword(ctx context.Context, userID, password string) error
}

// Well-known contact channels.
const (
	ChannelEmail = "email"
	ChannelPhone = "phone"
)

// ClaimAuthorizationDetails is the identity claim carrying UserInfo.AuthorizationDetails.
const ClaimAuthorizationDetails = "authorization_details"

// AuthorizationDetail is one RFC 9396 authorization detail: the actions allowed on the object
// of a type named by its identifier.
type AuthorizationDetail struct {
	Type       string   `json:"type"`
	Identifier string   `json:"identifier,omitempty"`
	Actions    []string `json:"actions,omitempty"`
}

// AuthorizationDetails are the RFC 9396 authorization details of a principal.
type AuthorizationDetails []AuthorizationDetail

// ActsFor reports whether the principal acts for the object of type named by identifier, whatever
// the actions.
func (d AuthorizationDetails) ActsFor(typ, identifier string) bool {
	for _, detail := range d {
		if detail.Type == typ && detail.Identifier == identifier {
			return true
		}
	}

	return false
}

// Allows reports whether action, which must be named, is allowed on the object of type named by
// identifier.
func (d AuthorizationDetails) Allows(typ, identifier, action string) bool {
	if action == "" {
		return false
	}

	for _, detail := range d {
		if detail.Type == typ && detail.Identifier == identifier && slices.Contains(detail.Actions, action) {
			return true
		}
	}

	return false
}

// Contact is one of a user's addresses on a channel.
type Contact struct {
	Address string `json:"address"`
	// Verified reports that the user proved ownership of Address.
	Verified bool `json:"verified"`
	// Primary marks the address preferred on its channel.
	Primary bool `json:"primary,omitempty"`
}

// UserInfo is returned by UserProvider. All fields are optional except ID.
type UserInfo struct {
	ID   string
	Name string
	// Contacts maps a channel to the user's addresses on it.
	Contacts map[string][]Contact
	// Scope is the user's maximal, space-separated scope: both the OIDC scope values
	// (openid, profile, email, ...) and any application-defined authorization scopes
	// (admin, items:write, ...).
	Scope                  string
	Claims                 map[string]any
	RequiresPasswordChange bool
	// AMR lets a claim mapper / external login / authenticator ASSERT the authentication.
	// On introspection it carries the session's recorded methods.
	AMR []string
	// ACR is the satisfied authentication context class of the current login.
	ACR string
	// ClientID is the client the introspected credential was issued to.
	ClientID string
	// Context is the session's application-defined selections, set on introspection.
	Context map[string]any
	// AuthorizationDetails are the objects and actions a subject API key is authorized for.
	AuthorizationDetails AuthorizationDetails
}

// PreferredContact returns the contact to present for channel.
func (info UserInfo) PreferredContact(channel string) (Contact, bool) {
	var best Contact

	score := -1

	for _, c := range info.Contacts[channel] {
		s := 0
		if c.Primary {
			s++
		}

		if c.Verified {
			s += 2
		}

		if s > score {
			best = c
			score = s
		}
	}

	return best, score >= 0
}

// ToUser returns user identity.
func (info UserInfo) ToUser() *user.Basic {
	claims := make(map[string]token.ClaimStrings, 4)

	if info.Name != "" {
		claims["name"] = token.ClaimStrings{info.Name}
	}

	if email, _ := info.PreferredContact(ChannelEmail); email.Verified && email.Address != "" {
		claims["email"] = token.ClaimStrings{email.Address}
	}

	if phone, _ := info.PreferredContact(ChannelPhone); phone.Verified && phone.Address != "" {
		claims["phone_number"] = token.ClaimStrings{phone.Address}
	}

	if info.ACR != "" {
		claims["acr"] = token.ClaimStrings{info.ACR}
	}

	if len(info.AMR) > 0 {
		claims["amr"] = token.ClaimStrings(info.AMR)
	}

	if len(info.AuthorizationDetails) > 0 {
		details := make(token.ClaimStrings, 0, len(info.AuthorizationDetails))

		for _, d := range info.AuthorizationDetails {
			if raw, err := json.Marshal(d); err == nil {
				details = append(details, string(raw))
			}
		}

		claims[ClaimAuthorizationDetails] = details
	}

	return user.NewIdentity(info.ID, info.Scope, claims)
}

// ExternalUserProvider is an optional extension of UserProvider, the shared
// identity-resolution hook for BOTH external IdP logins AND passwordless authenticators.
// Contacts from an IdP arrive unverified unless its TrustVerifiedContacts is set; the IdP's own
// flags are in info.Claims ("email_verified", "phone_number_verified") for the app to trust.
type ExternalUserProvider interface {
	FindOrCreateUser(ctx context.Context, method string, info UserInfo) (UserInfo, error)
}

// Registerer is an optional UserProvider for registering new user accounts.
type Registerer interface {
	// Register creates a new user account from a request carrying a username, a contact address
	// or both. Returns ErrUsernameTaken for a taken username (checked first), a
	// *ContactTakenError for a taken contact address, or an error wrapping
	// ErrInvalidRegistration for data the implementation does not accept. On a channel with
	// contact verification an address is taken only when another account holds it verified;
	// the account that proves it first keeps it.
	Register(ctx context.Context, req RegistrationRequest) (UserInfo, error)
}

// PasswordChanger is an optional UserProvider extension for changing a user's password.
type PasswordChanger interface {
	// ChangePassword changes the authenticated user's password after verifying currentPassword.
	// Used by the self-service flow on an active session.
	ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error
	// SetPassword sets a new password WITHOUT verifying a current one. It is called only to
	// complete a pending_password_change session and must clear RequiresPasswordChange.
	SetPassword(ctx context.Context, userID, newPassword string) error
}

// PasswordResetter is an optional UserProvider extension for resetting a forgotten password.
// Proving ownership of the account is the job of the configured reset methods.
type PasswordResetter interface {
	// FindUser resolves a username or email to its account, ErrUserNotFound when unknown.
	FindUser(ctx context.Context, identifier string) (UserInfo, error)
	// ResetPassword sets a new password for userID after a reset method approved the request.
	ResetPassword(ctx context.Context, userID, newPassword string) error
}

// ContactVerifier is an optional UserProvider extension for verifying contact addresses.
type ContactVerifier interface {
	// VerifyContact records address of userID on channel as verified and removes it from every
	// other account holding it unverified. Returns a *ContactTakenError when another account
	// already holds it verified.
	VerifyContact(ctx context.Context, userID, channel, address string) error
	// FindContact resolves the account holding address on channel verified, ErrUserNotFound when
	// none.
	FindContact(ctx context.Context, channel, address string) (UserInfo, error)
}

// ContactManager is an optional UserProvider extension for managing an account's contacts.
type ContactManager interface {
	// RemoveContact removes address of user on channel.
	RemoveContact(ctx context.Context, userID, channel, address string) error
	// SetPrimaryContact makes address the primary one of user on channel.
	SetPrimaryContact(ctx context.Context, userID, channel, address string) error
}

// ProfileManager is an optional UserProvider extension for user profile.
type ProfileManager interface {
	// GetProfile returns display/profile data for the authenticated user.
	GetProfile(ctx context.Context, userID string) (map[string]any, error)
	// UpdateProfile updates display/profile data for the authenticated user.
	UpdateProfile(ctx context.Context, userID string, data map[string]any) error
}

// PasswordPolicy decides whether a new password is acceptable, before it reaches the
// UserProvider.
type PasswordPolicy interface {
	// Validate returns an error wrapping ErrWeakPassword when password is not acceptable for
	// the account info.
	Validate(ctx context.Context, password string, info UserInfo) error
}

// RegistrationRequest carries the data for a new user registration.
type RegistrationRequest struct {
	Username string
	Password string
	// Contacts maps a channel to the address given for it, e.g. {"email": "...", "phone": "..."}.
	Contacts map[string]string
	Extra    map[string]any // custom data needed for registration
}
