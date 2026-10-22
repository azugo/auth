package contract

import "errors"

var (
	// ErrInvalidCredentials is returned when the supplied username/password is wrong.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrUserAlreadyExists matches a ContactTakenError.
	ErrUserAlreadyExists = errors.New("user already exists")
	// ErrUsernameTaken is returned by Registerer.Register when the username is taken.
	ErrUsernameTaken = errors.New("username taken")
	// ErrUserNotFound is returned by UserProvider.GetUser when the user ID is unknown.
	ErrUserNotFound = errors.New("user not found")
	// ErrWeakPassword is returned by a PasswordPolicy, or a UserProvider, for a new password
	// that is not acceptable; wrap it to say why.
	ErrWeakPassword = errors.New("password does not meet the policy")
	// ErrInvalidRegistration is returned for registration data it does not
	// accept; wrap it to say why.
	ErrInvalidRegistration = errors.New("invalid registration")
	// ErrInvalidContact is returned by ContactManager for a contact it does not accept; wrap it to
	// say why.
	ErrInvalidContact = errors.New("invalid contact")
)

// ContactTakenError is returned by Registerer.Register when the address on Channel is taken.
type ContactTakenError struct {
	Channel string
}

func (e *ContactTakenError) Error() string {
	return "contact address taken: " + e.Channel
}

// Is reports whether target is ErrUserAlreadyExists.
func (e *ContactTakenError) Is(target error) bool {
	return target == ErrUserAlreadyExists
}
