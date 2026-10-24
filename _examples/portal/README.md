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
`guest / guest123` is held at the `/password` page until it sets a new password, the same page
a signed-in user reaches from `/security` to change theirs.

## Portal rules

`rules.go` is an example login step (`auth.LoginSteps`): on their first sign-in every user is
held at the `/rules` page until they accept the portal rules, after any MFA or password step.
The accepted version is recorded per user and in the session context (`rules_version`, also in
the `id_token` and `/userinfo`); raising `RulesVersion` asks everyone again on their next
sign-in. Acceptances are kept in memory, so a restart asks again too.

## API keys

Signed-in users manage API keys on `/apikeys`: a key takes a name, any subset of the caller's
own scope (`admin` only sees the `admin` box) and an optional expiry, and its token is shown
once. Keys are listed with their status and can be rotated, which issues a new token and stops
the old one at once, or revoked. Creating or rotating a key needs a sign-in no older than five
minutes, the library's default step-up; sign in again if the page refuses it. Changing the
password offers to revoke every key as well.

A key is a bearer token: the portal mounts `middleware.APIKey()`, so it authenticates any
portal route, and `/api/me` answers with the caller and the scope the key carries:

```sh
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/me
```

Keys are kept in memory and are gone after a restart.

## Two-factor authentication

Signed-in users manage second factors on `/security`. TOTP shows a QR code for an
authenticator app, recovery issues one-time backup codes, and push asks for a device name
and is then approved out-of-band. A method may be added several times, once per device,
and each enrollment is removed on its own; recovery codes are a single set.

The `push` driver in `push/` is an example of an asynchronous method: it delivers nothing,
but logs the challenge it would have pushed. The `/mfa` page shows a six-digit transaction
code for the user to match against the device, and the sign-in waits there until the vendor
webhook approves it. Copy the `challenge_id` from the server log and call the webhook
with the secret from `.env`:

```sh
curl -X POST http://localhost:8080/auth/mfa/callback/push \
	-H "Content-Type: application/json" \
	-H "X-Callback-Secret: insecure-example-push-callback-secret" \
	--data '{"challenge_id": "<from the log>", "approved": true, "transaction": "<code from the log>", "device": "<device from the log>"}'
```

An approval must carry the transaction code shown on the `/mfa` page, standing in for the
user matching it on the device. `device` is optional; when present the matching enrollment is
marked as last used. Without `PUSH_CALLBACK_SECRET` the push method is not offered at all.

Then press "I have approved it" on the `/mfa` page to finish signing in. A denied request
(`"approved": false`) is spent; "Send a new request" issues a fresh challenge under the
resend cooldown and cap.
