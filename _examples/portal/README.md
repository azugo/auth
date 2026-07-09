# Auth portal example

A minimal server-side rendered portal built on `azugo.io/auth` with
[templ](https://templ.guide/) views. It wires `auth.New()` with the in-memory session
store, a first-party cookie-mode client and a hard-coded demo `UserProvider`.

## Run

Development configuration (server URL, auth secret, cookie settings) lives in `.env`
and is loaded on startup; real environment variables take precedence.

```sh
go generate ./...   # regenerate templ views
go run ./cmd/server
```

Open <http://localhost:8080> and sign in with `admin / admin123` or `user / user123`.
