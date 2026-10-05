package reset

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	"azugo.io/auth/contract"
)

// Driver is implemented by a reset method package and registered via Register.
type Driver interface {
	// Open creates a Method from the configuration entry.
	Open(cfg *contract.ResetMethodConfig) (Method, error)
}

var (
	driversMu sync.RWMutex
	drivers   = make(map[string]Driver)
)

// Register makes a Driver available under name.
//
// Panics on a nil or duplicate registration.
func Register(name string, d Driver) {
	driversMu.Lock()
	defer driversMu.Unlock()

	if d == nil {
		panic("reset: Register driver is nil")
	}

	if _, dup := drivers[name]; dup {
		panic("reset: Register called twice for driver " + name)
	}

	drivers[name] = d
}

func driver(name string) (Driver, error) {
	driversMu.RLock()
	defer driversMu.RUnlock()

	d, ok := drivers[name]
	if !ok {
		return nil, fmt.Errorf("reset: unknown driver %q", name)
	}

	return d, nil
}

func driverNames() []string {
	driversMu.RLock()
	defer driversMu.RUnlock()

	names := make([]string, 0, len(drivers))
	for name := range drivers {
		names = append(names, name)
	}

	return names
}

// Registry resolves reset methods by name.
type Registry interface {
	// Get returns the method available under name, or ErrUnknownMethod.
	Get(ctx context.Context, name string) (Method, error)
	// Names returns every available method name, configured entries first.
	Names(ctx context.Context) ([]string, error)
}

// Methods returns a Registry over methods built in code, for channels that need application
// hooks such as Link and Code. Names are listed sorted.
func Methods(methods map[string]Method) Registry {
	return staticRegistry(methods)
}

type staticRegistry map[string]Method

func (r staticRegistry) Get(_ context.Context, name string) (Method, error) {
	m, ok := r[name]
	if !ok {
		return nil, ErrUnknownMethod
	}

	return m, nil
}

func (r staticRegistry) Names(context.Context) ([]string, error) {
	return slices.Sorted(maps.Keys(r)), nil
}

type configRegistry struct {
	config *contract.Configuration

	mu     sync.Mutex
	opened map[string]*openedMethod
}

type openedMethod struct {
	config contract.ResetMethodConfig
	method Method
}

// NewConfigRegistry creates the default Registry over Configuration.PasswordResetMethods and
// the registered drivers.
func NewConfigRegistry(config *contract.Configuration) Registry {
	return &configRegistry{config: config, opened: make(map[string]*openedMethod)}
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
	names := make([]string, 0, len(r.config.PasswordResetMethods))

	for i := range r.config.PasswordResetMethods {
		e := r.config.PasswordResetMethods[i]
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

		if _, err := r.open(&contract.ResetMethodConfig{Name: d, Driver: d}); err == nil {
			names = append(names, d)
		}
	}

	return names, nil
}

// configured reports whether any entry references driver.
func (r *configRegistry) configured(driver string) bool {
	for i := range r.config.PasswordResetMethods {
		if r.config.PasswordResetMethods[i].Driver == driver {
			return true
		}
	}

	return false
}

func (r *configRegistry) entry(name string) (*contract.ResetMethodConfig, error) {
	for i := range r.config.PasswordResetMethods {
		if e := r.config.PasswordResetMethods[i]; e.Name == name || (e.Name == "" && e.Driver == name) {
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

	return &contract.ResetMethodConfig{Name: name, Driver: name}, nil
}

func (r *configRegistry) open(entry *contract.ResetMethodConfig) (Method, error) {
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

	m, err := d.Open(entry)
	if err != nil {
		return nil, fmt.Errorf("reset method %q: %w", entry.Name, err)
	}

	stored := *entry
	stored.Config = maps.Clone(entry.Config)
	r.opened[entry.Name] = &openedMethod{config: stored, method: m}

	return m, nil
}
