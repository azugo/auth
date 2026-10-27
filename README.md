# Azugo Auth

[![status-badge](https://ci.azugo.io/api/badges/azugo/auth/status.svg)](https://ci.azugo.io/azugo/auth)

> [!WARNING]
> This library is currently **EXPERIMENTAL** and breaking changes are expected!

Azugo framework authentication toolkit - OAuth 2.0 / OpenID Connect building blocks with PASETO
v4.local tokens.

## Features

* PASETO v4.local access tokens, session cookies and API keys with zero-downtime secret rotation.
* Pluggable user provider, session store, client registry and JTI allowlist.
* Cache-backed session and JTI stores out of the box.
* Self-service account management: registration per client policy, forced and self-service
  password change, a password policy, and password reset over pluggable methods (mailed link,
  texted code, out-of-band approval, or your own), each offered only when the account can use it.
* Login steps: application gates (`auth.LoginSteps(...)`) that hold a session at `pending_step`
  until resolved through `POST /steps/{name}` - tenant/role selection, first-party consent, a
  versioned usage agreement - with `POST /session/switch` to change the selection later; a switch
  that requires a step again takes effect only once the step is resolved, and the session stays
  on its previous selection meanwhile. The selection lives in `Session.Context` and reaches the
  `id_token` and `/userinfo` of the session's own client; another client receives only the keys
  its registration lists in `ContextClaims`.
* User contacts are per channel and may be several per channel (`UserInfo.Contacts`: address,
  verified and primary flags for `email`, `phone` or any channel of your own); only verified
  addresses are used for communication. `/userinfo` releases the preferred `email` /
  `phone_number` (verified primary first) with their `_verified` flags under the `email` /
  `phone` scopes.
* Contacts from an external IdP reach `auth.ExternalUserProvider.FindOrCreateUser` unverified;
  the IdP's `email_verified` / `phone_number_verified` stay in `UserInfo.Claims` for the app to
  decide on, or set `trust_verified_contacts` on a provider to keep its flags.
* Opt-in contact verification per channel (`auth.ContactVerification(auth.ChannelEmail, method)`,
  likewise `auth.ChannelPhone` or your own, with an `auth.ContactVerifier` user provider): a
  channel with addresses but none verified holds the login at the built-in `verify_<channel>`
  step ahead of MFA (one verified address is enough), a delivered link can be confirmed at
  `POST /account/contact/verify`, and a registration giving an address on a verified channel
  answers `202` uniformly so only the address owner learns whether the account already existed.
  The `202` carries `{"request", "interaction"}`: a delivered code is presented with that
  `request` at `POST /account/contact/verify` without logging in (a repeated registration gets a
  decoy that answers alike).
  Registration carries `contacts` per channel. On such a channel only a verified address is
  taken: several accounts may hold it unverified, and the first to prove it keeps it
  (`ContactVerifier.VerifyContact` drops it from the others).
  Every address the library receives is canonicalized before it reaches the user provider or
  any throttle key: trimmed, emails lowercased, phone numbers stripped of spaces and separators
  (`auth.DefaultAddressNormalizer`). Replace it with `auth.AddressNormalization(...)`, e.g. to
  add a country code, and use `a.NormalizeAddress(channel, address)` for your own lookups.
* Contact management for a signed-in user: `GET /account/contacts`, `POST /account/contacts`
  (a new address joins the account only after its proof), and with an `auth.ContactManager` user
  provider `POST /account/contacts/primary` and `POST /account/contacts/remove`.
* Step-up for sensitive actions, decided by the app (`auth.StepUp(policy)`): per action a maximum
  login age, minimum ACR and/or required methods (e.g. only a second factor, only the password,
  or nothing). The library asks about each of its own sensitive actions (contacts, password
  change, MFA enroll/revoke, identity unlink, session revoke/switch, profile update); the app
  guards its own with `a.RequireStepUp(ctx, token, "account.delete")` or
  `middleware.RequireStepUp(a, "account.delete")`. By default, adding or revoking a factor and
  adding, removing or making primary a contact need a second factor within 5 minutes on an
  account that had a factor before the session, and any authentication within 5 minutes
  otherwise (revoking a factor enrolled through the session needs nothing); return
  `auth.NoStepUp` from the policy to relax any of them. A session that falls short gets `401 insufficient_user_authentication`
  (RFC 9470) and re-authenticates in place at `POST /session/reauth` + `/session/reauth/verify`
  with the password (`auth.PasswordAuthenticator`) or an MFA factor enrolled before the
  session was created - no new login, other tokens keep working. Only methods that can reach
  the required level are offered; a factor that reaches it only with the password answers
  `"password": true` and takes both in one `/session/reauth/verify`.

## Usage

```go
	a, err := auth.New(app, cfg, users, sessions, clients)
	if err != nil {
		panic(err)
	}
```

Where `app` is a `*core.App`, `cfg` is an `*auth.Configuration`, `users` implements `auth.UserProvider` (just `GetUser`; add `auth.PasswordAuthenticator` for local passwords - without it there is no password login, change, reset or registration), `sessions` a `session.Store` and
`clients` a `client.Registry`. A `private_key_jwt` client must address its assertion to the
issuer identifier (`aud`).

`auth.Auth` is a transport-free service that takes a request struct and return a result
+ directive struct, with no HTTP dependency. Two optional layers sit on top:

* `azugo.io/auth/routes` - azugo HTTP adapters. `routes.Bind(router, prefix, a)` mounts every group `a`'s
  configuration supports; pass one or more `routes.Group` values (or `routes.OIDC()`) to restrict it.
  For a `Handler` built with `routes.New(a, ...)` and mounted manually at custom paths, pass
  `routes.MountPrefix` and/or `routes.TokenEndpoint`/`UserinfoEndpoint`/`JWKSEndpoint` so the
  discovery document still reports correct URLs.
* `azugo.io/auth/middleware` - `middleware.Auth(a, ...)` resolves `ctx.User()` from the
  `Authorization` header (and, with `middleware.Cookie()`, the session cookie) and answers a
  credential failing its DPoP binding with the RFC 9449 `WWW-Authenticate: DPoP` challenge;
  `middleware.DPoP(a)` does just the latter for handlers that read the token themselves through
  `a.ReadSessionToken(ctx)`, which extracts the credential without checking its binding
  (`routes.Bind` mounts it; a `Handler` mounted manually needs it in front; an app that also
  mounts `middleware.Auth` with `Use` calls `routes.Bind` first, since `Use` wraps only the routes
  registered after it and two verifiers would see the single-use proof twice); a resource
  server serving specific clients should pass `middleware.Audience(...)` so tokens issued to
  other clients are not accepted (`middleware.IntrospectionAudience(...)` for
  `middleware.Introspection(a, ...)`, which checks DPoP proofs;
  `middleware.RequireAuth(...)` halts the chain for an anonymous request, optionally redirecting
  (`middleware.RedirectTo`, `middleware.ReturnTo`) instead of returning a JSON 401.

A handler of your own that calls the services verifies the DPoP binding once per request the same
way: `middleware.Auth` or `middleware.DPoP` in front and `a.ReadSessionToken(ctx)` inside, or no
middleware and a single `a.ReadAccessToken(ctx)` inside, answering its error with `ctx.Error`. The
token-consuming services (`IntrospectToken`, `UserInfoClaims`, `RequireStepUp`, ...) take the
token as given, so one read straight from the `Authorization` header skips the check; the issuing
ones (`Login`, `Refresh`, the grants, `Register`, `ResetPassword`) verify the proof passed as
`DPoP`, read with `a.ReadDPoPProof(ctx)`.

See `_examples/portal` for a complete server-side-rendered app wiring all of the above together.

## Environment variables

* `AUTH_SECRET` - PASETO local secret used to seal tokens (min. 32 bytes).
* `AUTH_SAME_SITE` - Session cookie `SameSite` policy: `strict`, `lax` or `none`. Default `strict`.
* `AUTH_COOKIE_NAME` - Session cookie name. Default `session`.
* `AUTH_COOKIE_PATH` - Session cookie path. Default: the auth mount prefix.
* `AUTH_LOGOUT_KEEPS_COOKIE` - Make logout clear the browser cookie only, leaving the session valid
  for a cookie shared across apps. Default `false`: logout revokes the session server-side.
* `AUTH_LOGOUT_POLICY` - What `GET /logout` must carry before it ends a session (OpenID Connect
  RP-Initiated Logout). Set one whenever `AUTH_SAME_SITE` is relaxed from `strict`, since a `lax`
  cookie rides a cross-site navigation and a bare link would otherwise log the user out.
  * unset - the session cookie alone is enough. Default.
  * `confirm` - an `id_token_hint` this server issued for the session, or the user confirming by
    posting back from a page of this origin (checked via the browser's `Sec-Fetch-Site` or
    `Origin` header, so a cross-site form cannot confirm even with `none`). Supply the
    confirmation page with `routes.LogoutConfirmation(handler)`.
  * `id_token_hint` - the hint is required and there is no confirmation path, so a relying party
    must identify the session it is ending.
* `AUTH_ACCESS_TOKEN_TTL` - Access token lifetime. Default `20m`.
* `AUTH_PENDING_TTL` - How long a login, or a session switch, may wait on its steps (MFA,
  contact verification, app steps), and the lifetime of its step token. Default `30m`.
* `AUTH_SESSION_TTL` - Session lifetime. Default `8h`.
* `AUTH_CODE_TTL` - Authorization-code lifetime. Default `60s`.
* `AUTH_EXTERNAL_STATE_TTL` - Time a user has to complete an external IdP round-trip, from redirect
  to callback. Default `15m`.
* `AUTH_PASSWORD_RESET_TTL` - Lifetime of a password-reset token. Default `1h`.
* `AUTH_CONTACT_VERIFICATION_TTL` - Lifetime of a contact verification request. Default `24h`.
* `AUTH_PASSWORD_MIN_LENGTH` / `AUTH_PASSWORD_MAX_LENGTH` - Length bounds of the default password
  policy, which also refuses a password containing the account's username, email or name.
  Defaults `8` / `128`. Replace the policy with the `auth.PasswordPolicy(...)` option.
* `AUTH_CLOCK_SKEW` - Leeway allowed on external `id_token` time claims, inherited by every
  provider that does not set `clock_skew` itself, and on the `max_age` of an authorization
  request. Default `1m`; keep it under `2m`, and use `0` to validate strictly.
* `AUTH_DPOP_PROOF_WINDOW` - How far a DPoP proof's `iat` may lie from the current time, past or
  future. Default `1m`; keep it under `2m`. A client with the nonce DPoP policy is bounded by
  `AUTH_DPOP_NONCE_WINDOW` (default `1m`) instead.
* `AUTH_BASE_URL` - Public base URL used to resolve the issuer and default cookie path. Optional;
  derived from the request otherwise (needed behind a proxy or on a split origin).
* `AUTH_ISSUER` - OIDC issuer identifier. Optional; derived from the request base URL when unset.
* `AUTH_THROTTLE_ENABLED` - Enable the brute-force lockout guard. Default `true`.
* `AUTH_THROTTLE_MAX_ATTEMPTS` - Attempts before lockout. Default `5`.
* `AUTH_THROTTLE_WINDOW` - Attempt-counting window. Default `15m`.
* `AUTH_THROTTLE_LOCKOUT_TTL` - How long a key stays blocked once it hits the limit. Default `15m`.
* `AUTH_THROTTLE_MFA_RESEND_COOLDOWN` - MFA code resend cooldown. Default `60s`.
* `AUTH_THROTTLE_MFA_MAX_RESENDS` - Maximum MFA code resends. Default `3`.
* `AUTH_THROTTLE_EXTERNAL_START_MAX` - External IdP round-trips one caller may start per
  `AUTH_THROTTLE_WINDOW`, bounding unauthenticated growth of the round-trip state cache. Default `300`; a negative value disables the cap.
* `AUTH_THROTTLE_REGISTRATION_MAX` - Accounts one caller may register per `AUTH_THROTTLE_WINDOW`,
  created or rejected alike. Default `20`; a negative value disables the cap.
* `AUTH_THROTTLE_CONTACT_DELIVERY_MAX` - Verification messages one account has sent to a contact
  address per `AUTH_THROTTLE_WINDOW`. Default `5`; a negative value disables the cap.
* `AUTH_THROTTLE_CONTACT_SEND_MAX` - Verification messages one user may have sent on a channel
  per `AUTH_CONTACT_VERIFICATION_TTL`, whichever addresses they go to. Default `10`; a negative
  value disables the cap.
* `AUTH_KEYS_PRIMARY` (or `AUTH_KEYS_PRIMARY_FILE`) - PEM-encoded primary signing key (RSA or
  ECDSA private key). Enables JWT/JWKS signing; unset means introspect-only mode.
* `AUTH_KEYS_PRIMARY_ALGORITHM` - Primary key algorithm: `RS256`, `RS384`, `RS512`, `ES256`,
  `ES384` or `ES512`. Optional; defaults to the curve-mandated algorithm for an EC key, or
  `RS256` for RSA.
* `AUTH_KEYS_SECONDARY` (or `AUTH_KEYS_SECONDARY_FILE`) - One or more concatenated PEM-encoded
  public keys accepted for verification alongside the primary key (e.g. during key rotation).
