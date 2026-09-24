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

	// Portal pages render failures as HTML.
	a.RouterOptions().ErrorHandler = r.errorPage
	a.RouterOptions().NotFound = r.notFound

	a.Get("/healthz", healthz.Handler())

	a.Use(middleware.Auth(a.Auth(), middleware.Cookie()))

	a.Get("/", r.home)
	a.Get("/error", r.errorRedirected)
	a.Get("/login", r.loginForm)
	a.Post("/login", r.login)
	a.Get("/mfa", r.mfaPage)
	a.Post("/mfa/verify", r.mfaVerify)
	a.Post("/mfa/begin", r.mfaBegin)
	a.Post("/logout", r.logout)

	routes.Bind(a, "/auth", a.Auth())

	sessions := a.Group("/sessions")
	sessions.Use(middleware.RequireAuth(middleware.RedirectTo("/login"), middleware.ReturnTo()))
	sessions.Get("", r.sessionsPage)
	sessions.Post("/{id}/revoke", r.revokeSession)

	security := a.Group("/security")
	security.Use(middleware.RequireAuth(middleware.RedirectTo("/login"), middleware.ReturnTo()))
	security.Get("", r.securityPage)
	security.Post("/mfa/{method}/enroll", r.mfaEnroll)
	security.Post("/mfa/{method}/finish", r.mfaEnrollFinish)
	security.Post("/mfa/{method}/{id}/revoke", r.mfaRevoke)

	return nil
}
