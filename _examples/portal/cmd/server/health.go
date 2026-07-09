package main

import (
	"example/portal"

	"azugo.io/azugo/server"
	"azugo.io/core/cli"
)

func init() {
	cli.Register(server.HealthCommand("/healthz", server.Options{
		AppName:       "Auth Portal Example",
		AppVer:        Version,
		Configuration: portal.NewConfiguration(),
	}))
}
