// Package routes registers the example portal HTTP routes.
package routes

import (
	"example/portal"

	"azugo.io/azugo/healthz"
)

type router struct {
	*portal.App
}

// Init registers all HTTP routes.
func Init(a *portal.App) error {
	r := &router{App: a}

	a.Get("/healthz", healthz.Handler())

	a.Get("/", r.home)
	a.Get("/login", r.loginForm)
	a.Post("/login", r.login)

	return nil
}
