# Azugo Auth

[![status-badge](https://ci.azugo.io/api/badges/azugo/auth/status.svg)](https://ci.azugo.io/azugo/auth)

> [!WARNING]
> This library is currently **EXPERIMENTAL** and breaking changes are expected!

Azugo framework authentication toolkit — OAuth 2.0 / OpenID Connect building blocks with PASETO
v4.local tokens.

## Features

* PASETO v4.local access tokens, session cookies and API keys with zero-downtime secret rotation.
* Pluggable user provider, session store, client registry and JTI allowlist.
* Cache-backed session and JTI stores out of the box.

## Usage

```go
	a, err := auth.New(app, cfg, users, sessions, clients)
	if err != nil {
		panic(err)
	}
```

Where `app` is a `*core.App`, `cfg` is an `*auth.Configuration`, `users` implements `auth.UserProvider`, `sessions` a `session.Store` and
`clients` a `client.Registry`.

`auth.Auth` is a transport-free service that takes a request struct and return a result
+ directive struct, with no HTTP dependency. Two optional layers sit on top:

* `azugo.io/auth/routes` - azugo HTTP adapters. `routes.Bind(router, prefix, a)` mounts every group `a`'s
  configuration supports; pass one or more `routes.Group` values (or `routes.OIDC()`) to restrict it.
  For a `Handler` built with `routes.New(a, ...)` and mounted manually at custom paths, pass
  `routes.MountPrefix` and/or `routes.TokenEndpoint`/`UserinfoEndpoint`/`JWKSEndpoint` so the
  discovery document still reports correct URLs.
* `azugo.io/auth/middleware` - `middleware.Auth(a, ...)` resolves `ctx.User()` from the
  `Authorization` header (and, with `middleware.Cookie()`, the session cookie);
  `middleware.RequireAuth(...)` halts the chain for an anonymous request, optionally redirecting
  (`middleware.RedirectTo`, `middleware.ReturnTo`) instead of returning a JSON 401.

See `_examples/portal` for a complete server-side-rendered app wiring all of the above together.

## Environment variables

* `AUTH_SECRET` - PASETO local secret used to seal tokens (min. 32 bytes).
* `AUTH_SECURE` - Mark session cookies as `Secure`. Default `true`.
* `AUTH_SAME_SITE` - Session cookie `SameSite` policy: `strict`, `lax` or `none`. Default `strict`.
* `AUTH_COOKIE_NAME` - Session cookie name. Default `__session`.
* `AUTH_COOKIE_PATH` - Session cookie path. Default: the auth mount prefix.
* `AUTH_LOGOUT_INVALIDATES_COOKIE` - Make logout authoritative server-side. Default `true`.
* `AUTH_ACCESS_TOKEN_TTL` - Access token lifetime. Default `20m`.
* `AUTH_SESSION_TTL` - Session lifetime. Default `8h`.
* `AUTH_CODE_TTL` - Authorization-code lifetime. Default `60s`.
* `AUTH_EXTERNAL_STATE_TTL` - Time a user has to complete an external IdP round-trip, from redirect
  to callback. Default `15m`.
* `AUTH_CLOCK_SKEW` - Leeway allowed on external `id_token` time claims, inherited by every
  provider that does not set `clock_skew` itself. Default `1m`; keep it under `2m`, and use `0`
  to validate strictly.
* `AUTH_BASE_URL` - Public base URL used to resolve the issuer and default cookie path. Optional;
  derived from the request otherwise (needed behind a proxy or on a split origin).
* `AUTH_ISSUER` - OIDC issuer identifier. Optional; derived from the request base URL when unset.
* `AUTH_THROTTLE_ENABLED` - Enable the brute-force lockout guard. Default `true`.
* `AUTH_THROTTLE_MAX_ATTEMPTS` - Attempts before lockout. Default `5`.
* `AUTH_THROTTLE_WINDOW` - Attempt-counting window. Default `15m`.
* `AUTH_THROTTLE_LOCKOUT_TTL` - Lockout duration. Default `15m`.
* `AUTH_THROTTLE_MFA_RESEND_COOLDOWN` - MFA code resend cooldown. Default `60s`.
* `AUTH_THROTTLE_MFA_MAX_RESENDS` - Maximum MFA code resends. Default `3`.
* `AUTH_KEYS_PRIMARY` (or `AUTH_KEYS_PRIMARY_FILE`) - PEM-encoded primary signing key (RSA or
  ECDSA private key). Enables JWT/JWKS signing; unset means introspect-only mode.
* `AUTH_KEYS_PRIMARY_ALGORITHM` - Primary key algorithm: `RS256`, `RS384`, `RS512`, `ES256`,
  `ES384` or `ES512`. Optional; defaults to the curve-mandated algorithm for an EC key, or
  `RS256` for RSA.
* `AUTH_KEYS_SECONDARY` (or `AUTH_KEYS_SECONDARY_FILE`) - One or more concatenated PEM-encoded
  public keys accepted for verification alongside the primary key (e.g. during key rotation).
