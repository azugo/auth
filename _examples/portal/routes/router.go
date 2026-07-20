// Package routes registers the example portal HTTP routes.
package routes

import (
	"example/portal"

	"azugo.io/auth/middleware"
	"azugo.io/auth/routes"

	"azugo.io/azugo/healthz"
)

type router struct {
	*portal.App
}

// Init registers all HTTP routes.
func Init(a *portal.App) error {
	r := &router{App: a}

	a.Get("/healthz", healthz.Handler())

	a.Use(middleware.Auth(a.Auth(), middleware.Cookie()))

	a.Get("/", r.home)
	a.Get("/login", r.loginForm)
	a.Post("/logout", r.logout)

	routes.Bind(a, "/auth", a.Auth())

	sessions := a.Group("/sessions")
	sessions.Use(middleware.RequireAuth(middleware.RedirectTo("/login"), middleware.ReturnTo()))
	sessions.Get("", r.sessionsPage)
	sessions.Post("/{id}/revoke", r.revokeSession)

	return nil
}
