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
curl -X POST http://localhost:8080/auth/mfa/push/callback \
	-H "Content-Type: application/json" \
	-H "X-Callback-Secret: insecure-example-push-callback-secret" \
	--data '{"challenge_id": "<from the log>", "approved": true, "device": "<device from the log>"}'
```

`device` is optional; when present the matching enrollment is marked as last used.

Then press "I have approved it" on the `/mfa` page to finish signing in.
