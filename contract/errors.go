package contract

import "errors"

var (
	// ErrInvalidCredentials is returned when the supplied username/password is wrong.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrUserAlreadyExists is returned by Registerer.Register when the account is taken.
	ErrUserAlreadyExists = errors.New("user already exists")
	// ErrUserNotFound is returned by UserProvider.GetUser when the user ID is unknown.
	ErrUserNotFound = errors.New("user not found")
	// ErrWeakPassword is returned by a PasswordPolicy, or a UserProvider, for a new password
	// that is not acceptable; wrap it to say why.
	ErrWeakPassword = errors.New("password does not meet the policy")
)
