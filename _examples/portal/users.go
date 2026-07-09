package portal

import (
	"context"
	"crypto/subtle"

	"azugo.io/auth"
)

type demoUser struct {
	info     auth.UserInfo
	password string
}

// DemoUsers is a hard-coded in-memory UserProvider for the example.
type DemoUsers struct {
	users map[string]demoUser
}

// NewDemoUsers creates the demo user provider with two predefined accounts.
func NewDemoUsers() *DemoUsers {
	return &DemoUsers{
		users: map[string]demoUser{
			"admin": {
				password: "admin123",
				info: auth.UserInfo{
					ID:    "u-0001",
					Name:  "Portal Admin",
					Email: "admin@example.com",
					Scope: "openid profile admin",
				},
			},
			"user": {
				password: "user123",
				info: auth.UserInfo{
					ID:    "u-0002",
					Name:  "Portal User",
					Email: "user@example.com",
					Scope: "openid profile",
				},
			},
		},
	}
}

// Authenticate implements auth.UserProvider.
func (p *DemoUsers) Authenticate(_ context.Context, username, password string) (auth.UserInfo, error) {
	u, ok := p.users[username]
	if !ok || subtle.ConstantTimeCompare([]byte(u.password), []byte(password)) != 1 {
		return auth.UserInfo{}, auth.ErrInvalidCredentials
	}

	return u.info, nil
}

// GetUser implements auth.UserProvider.
func (p *DemoUsers) GetUser(_ context.Context, userID string) (auth.UserInfo, error) {
	for _, u := range p.users {
		if u.info.ID == userID {
			return u.info, nil
		}
	}

	return auth.UserInfo{}, auth.ErrUserNotFound
}
