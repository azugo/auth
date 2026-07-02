// Package contract holds the cross-cutting types and interfaces shared between the
// base auth package and the plugin packages.
package contract

import (
	"context"
)

// UserProvider validates credentials and loads user data.
type UserProvider interface {
	// Authenticate returns a UserInfo on success or an error ErrInvalidCredentials.
	Authenticate(ctx context.Context, username, password string) (UserInfo, error)
	// GetUser returns the current state of a user by ID.
	GetUser(ctx context.Context, userID string) (UserInfo, error)
}

// UserInfo is returned by UserProvider. All fields are optional except ID.
type UserInfo struct {
	ID                     string
	Name                   string
	Email                  string
	Scope                  string
	Claims                 map[string]any
	RequiresPasswordChange bool
	// AMR lets a claim mapper / external login / authenticator ASSERT the authentication
	// methods of this login - RFC 8176 values, e.g. ["mfa","hwk"].
	AMR []string
}

// ExternalUserProvider is an optional extension of UserProvider, the shared
// identity-resolution hook for BOTH external IdP logins AND passwordless authenticators.
type ExternalUserProvider interface {
	FindOrCreateUser(ctx context.Context, method string, info UserInfo) (UserInfo, error)
}

// Registerer is an optional UserProvider for registering new user accounts.
type Registerer interface {
	// Register creates a new user account. Returns ErrUserAlreadyExists if taken.
	Register(ctx context.Context, req RegistrationRequest) (UserInfo, error)
}

// PasswordChanger is an optional UserProvider extension for changing a user's password.
type PasswordChanger interface {
	// ChangePassword changes the authenticated user's password after verifying currentPassword.
	// Used by the self-service flow on an active session.
	ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error
	// SetPassword sets a new password WITHOUT verifying a current one. It is called only to
	// complete a pending_password_change session.
	SetPassword(ctx context.Context, userID, newPassword string) error
}

// PasswordResetter is an optional UserProvider extension for reseting forgotten password.
type PasswordResetter interface {
	// RequestPasswordReset initiates a reset flow (e.g. sends an email with a token).
	RequestPasswordReset(ctx context.Context, identifier string) error
	// ResetPassword sets a new password using a verified reset token (no old password needed).
	ResetPassword(ctx context.Context, token, newPassword string) error
}

// ProfileManager is an optional UserProvider extension for user profile.
type ProfileManager interface {
	// GetProfile returns display/profile data for the authenticated user.
	GetProfile(ctx context.Context, userID string) (map[string]any, error)
	// UpdateProfile updates display/profile data for the authenticated user.
	UpdateProfile(ctx context.Context, userID string, data map[string]any) error
}

// RegistrationRequest carries the data for a new user registration.
type RegistrationRequest struct {
	Username string
	Email    string
	Password string
	Extra    map[string]any // custom data needed for registration
}
