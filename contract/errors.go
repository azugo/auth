package contract

import "errors"

var (
	// ErrInvalidCredentials is returned when the supplied username/password is wrong.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrUserAlreadyExists is returned by Registerer.Register when the account is taken.
	ErrUserAlreadyExists = errors.New("user already exists")
	// ErrUserNotFound is returned by UserProvider.GetUser when the user ID is unknown.
	ErrUserNotFound = errors.New("user not found")
)
