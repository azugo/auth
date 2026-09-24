package mfa

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	"azugo.io/auth/contract"
)

// Registry resolves MFA methods by name.
type Registry interface {
	// Get returns the method available under name, or ErrUnknownMethod.
	Get(ctx context.Context, name string) (Method, error)
	// Names returns every available method name, configured entries first.
	Names(ctx context.Context) ([]string, error)
}

type configRegistry struct {
	config *contract.Configuration
	store  Store

	mu     sync.Mutex
	opened map[string]*openedMethod
}

type openedMethod struct {
	config contract.MFAMethodConfig
	method Method
}

// NewConfigRegistry creates the default Registry.
func NewConfigRegistry(config *contract.Configuration, store Store) Registry {
	return &configRegistry{config: config, store: store, opened: make(map[string]*openedMethod)}
}

// Get returns the method available under name.
func (r *configRegistry) Get(_ context.Context, name string) (Method, error) {
	entry, err := r.entry(name)
	if err != nil {
		return nil, err
	}

	return r.open(entry)
}

// Names returns every available method name, dropping entries that fail to open.
func (r *configRegistry) Names(_ context.Context) ([]string, error) {
	names := make([]string, 0, len(r.config.MFAMethods))

	for i := range r.config.MFAMethods {
		e := r.config.MFAMethods[i]
		if e.Name == "" {
			e.Name = e.Driver
		}

		if _, err := r.open(&e); err == nil {
			names = append(names, e.Name)
		}
	}

	drivers := driverNames()
	slices.Sort(drivers)

	for _, d := range drivers {
		if r.configured(d) {
			continue
		}

		if _, err := r.open(&contract.MFAMethodConfig{Name: d, Driver: d}); err == nil {
			names = append(names, d)
		}
	}

	return names, nil
}

// configured reports whether any entry references driver.
func (r *configRegistry) configured(driver string) bool {
	for i := range r.config.MFAMethods {
		if r.config.MFAMethods[i].Driver == driver {
			return true
		}
	}

	return false
}

func (r *configRegistry) entry(name string) (*contract.MFAMethodConfig, error) {
	for i := range r.config.MFAMethods {
		if e := r.config.MFAMethods[i]; e.Name == name || (e.Name == "" && e.Driver == name) {
			e.Name = name

			return &e, nil
		}
	}

	if r.configured(name) {
		return nil, ErrUnknownMethod
	}

	if _, err := driver(name); err != nil {
		return nil, ErrUnknownMethod
	}

	return &contract.MFAMethodConfig{Name: name, Driver: name}, nil
}

func (r *configRegistry) open(entry *contract.MFAMethodConfig) (Method, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if cached, ok := r.opened[entry.Name]; ok &&
		cached.config.Driver == entry.Driver &&
		maps.Equal(cached.config.Config, entry.Config) {
		return cached.method, nil
	}

	d, err := driver(entry.Driver)
	if err != nil {
		return nil, err
	}

	m, err := d.Open(r.store, entry)
	if err != nil {
		return nil, fmt.Errorf("mfa method %q: %w", entry.Name, err)
	}

	stored := *entry
	stored.Config = maps.Clone(entry.Config)
	r.opened[entry.Name] = &openedMethod{config: stored, method: m}

	return m, nil
}
