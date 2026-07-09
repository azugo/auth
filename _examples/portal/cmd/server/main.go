package main

import (
	"azugo.io/core/cli"
	"github.com/joho/godotenv"
)

// Version of the example portal.
var Version = "1.0.0-dev"

func main() {
	_ = godotenv.Load()

	cli.Run(cli.Options{
		Use:     "portal",
		Short:   "Auth portal example",
		Long:    "Starts the example auth portal web server by default.",
		Version: Version,
	})
}
