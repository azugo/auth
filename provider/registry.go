package provider

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"azugo.io/auth/contract"
)

// ErrNotFound is returned when no configured provider matches the name.
var ErrNotFound = errors.New("external provider not found")

// Registry resolves external providers by name.
type Registry interface {
	// Get returns the provider configured under name.
	Get(ctx context.Context, name string) (Provider, *contract.ExternalProviderConfig, error)
}

// Prewarmer is an optional Registry extension that opens the currently-configured providers
// to validate configuration.
type Prewarmer interface {
	Prewarm(ctx context.Context) error
}

type configRegistry struct {
	config *contract.Configuration

	mu     sync.Mutex
	opened map[string]*openedProvider
}

type openedProvider struct {
	config   contract.ExternalProviderConfig
	provider Provider
}

// NewConfigRegistry creates the default Registry.
func NewConfigRegistry(config *contract.Configuration) Registry {
	return &configRegistry{config: config, opened: make(map[string]*openedProvider)}
}

// Get returns the provider configured under name.
func (r *configRegistry) Get(_ context.Context, name string) (Provider, *contract.ExternalProviderConfig, error) {
	var entry *contract.ExternalProviderConfig

	for i := range r.config.Providers {
		if e := &r.config.Providers[i]; e.Name == name || (e.Name == "" && e.Driver == name) {
			entry = e

			break
		}
	}

	if entry == nil {
		return nil, nil, ErrNotFound
	}

	p, err := r.open(name, entry)
	if err != nil {
		return nil, nil, err
	}

	if entry.LogoutAfterAuth {
		if _, ok := p.(Logouter); !ok {
			return nil, nil, fmt.Errorf("provider %q: logout_after_auth requires driver %q to support RP-initiated logout", name, entry.Driver)
		}
	}

	cfg := *entry

	return p, &cfg, nil
}

func (r *configRegistry) open(name string, entry *contract.ExternalProviderConfig) (Provider, error) {
	skew := r.config.ClockSkew
	if entry.ClockSkew != nil {
		skew = *entry.ClockSkew
	}

	effective := *entry
	effective.ClockSkew = &skew

	r.mu.Lock()
	defer r.mu.Unlock()

	if cached, ok := r.opened[name]; ok &&
		cached.config.Driver == effective.Driver &&
		cached.config.ClientID == effective.ClientID &&
		cached.config.ClientSecret == effective.ClientSecret &&
		cached.config.RedirectURL == effective.RedirectURL &&
		cached.config.EffectiveClockSkew() == effective.EffectiveClockSkew() &&
		slices.Equal(cached.config.Scopes, effective.Scopes) &&
		maps.Equal(cached.config.Config, effective.Config) {
		return cached.provider, nil
	}

	d, err := driver(entry.Driver)
	if err != nil {
		return nil, err
	}

	p, err := d.Open(&effective)
	if err != nil {
		return nil, fmt.Errorf("provider %q: %w", name, err)
	}

	stored := effective
	stored.Scopes = slices.Clone(effective.Scopes)
	stored.Config = maps.Clone(effective.Config)
	r.opened[name] = &openedProvider{config: stored, provider: p}

	return p, nil
}

// Prewarm opens every currently-configured provider.
func (r *configRegistry) Prewarm(_ context.Context) error {
	for i := range r.config.Providers {
		entry := &r.config.Providers[i]

		name := entry.Name
		if name == "" {
			name = entry.Driver
		}

		if _, err := r.open(name, entry); err != nil {
			return err
		}
	}

	return nil
}
