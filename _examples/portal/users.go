package portal

import (
	"context"
	"crypto/subtle"
	"sync"

	"azugo.io/auth"
)

type demoUser struct {
	info     auth.UserInfo
	password string
}

// DemoUsers is a hard-coded in-memory UserProvider for the example, with self-service
// password changes.
type DemoUsers struct {
	mu    sync.Mutex
	users map[string]demoUser
}

// NewDemoUsers creates the demo user provider with three predefined accounts, one of which
// must change its password on first sign-in.
func NewDemoUsers() *DemoUsers {
	return &DemoUsers{
		users: map[string]demoUser{
			"guest": {
				password: "guest123",
				info: auth.UserInfo{
					ID:                     "u-0003",
					Name:                   "Portal Guest",
					Email:                  "guest@example.com",
					Scope:                  "openid profile",
					RequiresPasswordChange: true,
				},
			},
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
	p.mu.Lock()
	defer p.mu.Unlock()

	u, ok := p.users[username]
	if !ok || subtle.ConstantTimeCompare([]byte(u.password), []byte(password)) != 1 {
		return auth.UserInfo{}, auth.ErrInvalidCredentials
	}

	return u.info, nil
}

// GetUser implements auth.UserProvider.
func (p *DemoUsers) GetUser(_ context.Context, userID string) (auth.UserInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	name, ok := p.username(userID)
	if !ok {
		return auth.UserInfo{}, auth.ErrUserNotFound
	}

	return p.users[name].info, nil
}

// username finds the account name of userID; the caller holds mu.
func (p *DemoUsers) username(userID string) (string, bool) {
	for name, u := range p.users {
		if u.info.ID == userID {
			return name, true
		}
	}

	return "", false
}

// ChangePassword implements auth.PasswordChanger.
func (p *DemoUsers) ChangePassword(_ context.Context, userID, currentPassword, newPassword string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	name, ok := p.username(userID)
	if !ok {
		return auth.ErrUserNotFound
	}

	u := p.users[name]
	if subtle.ConstantTimeCompare([]byte(u.password), []byte(currentPassword)) != 1 {
		return auth.ErrInvalidCredentials
	}

	u.password = newPassword
	p.users[name] = u

	return nil
}

// SetPassword implements auth.PasswordChanger.
func (p *DemoUsers) SetPassword(_ context.Context, userID, newPassword string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	name, ok := p.username(userID)
	if !ok {
		return auth.ErrUserNotFound
	}

	u := p.users[name]
	u.password = newPassword
	u.info.RequiresPasswordChange = false
	p.users[name] = u

	return nil
}
