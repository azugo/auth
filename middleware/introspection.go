package middleware

import (
	"net/url"
	"slices"
	"sync"
	"time"

	"azugo.io/auth"
	"azugo.io/auth/dpop"

	"azugo.io/azugo"
	"azugo.io/core/cache"
	"azugo.io/core/http"
	"github.com/goccy/go-json"
)

// ClientCredentials are the client_secret_post credentials the Introspection middleware
// authenticates with at the remote introspection endpoint.
type ClientCredentials struct {
	ClientID string
	Secret   string
}

// IntrospectionOption configures the Introspection middleware.
type IntrospectionOption interface {
	apply(o *introspectionOptions)
}

type introspectionOptions struct {
	cacheTTL  time.Duration
	audiences []string
}

// IntrospectionAudience restricts Introspection to tokens whose audience or client_id is one of
// the given client IDs.
func IntrospectionAudience(clientIDs ...string) IntrospectionOption {
	return introspectionAudience(clientIDs)
}

type introspectionAudience []string

func (o introspectionAudience) apply(opts *introspectionOptions) {
	opts.audiences = o
}

// IntrospectionCacheTTL caps the positive-result cache TTL.
type IntrospectionCacheTTL time.Duration

func (o IntrospectionCacheTTL) apply(opts *introspectionOptions) {
	opts.cacheTTL = time.Duration(o)
}

// NoIntrospectionCache forces strict per-request introspection.
func NoIntrospectionCache() IntrospectionOption {
	return IntrospectionCacheTTL(0)
}

// Introspection builds an Auth middleware for a resource server: opaque Bearer and DPoP tokens are
// validated by POSTing them to the auth server's RFC 7662 introspection endpoint, a DPoP-bound one
// also by its proof through a, whose base URL, clock skew and proof replay list it shares; a
// credential failing its DPoP binding is answered with the RFC 9449 challenge.
func Introspection(a *auth.Auth, endpoint string, creds ClientCredentials, opts ...IntrospectionOption) azugo.RequestHandlerFunc {
	o := introspectionOptions{cacheTTL: 30 * time.Second}
	for _, opt := range opts {
		opt.apply(&o)
	}

	var (
		once    sync.Once
		results cache.Instance[auth.IntrospectionResponse]
	)

	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			tok, _ := dpop.Credential(ctx.Header.Get(http.HeaderAuthorization))
			if tok == "" {
				next(ctx)

				return
			}

			once.Do(func() {
				if o.cacheTTL > 0 {
					results, _ = cache.Create[auth.IntrospectionResponse](ctx.App().Cache(), "auth:introspection", cache.MemoryCache)
				}
			})

			// Only active responses are cached, in a cache shared by every instance, so the
			// audience is checked below on hits and misses alike.
			var res auth.IntrospectionResponse
			if results != nil {
				res, _ = results.Get(ctx, tok)
			}

			if !res.Active {
				body, err := ctx.HTTPClient().PostForm(endpoint, url.Values{
					"token":         {tok},
					"client_id":     {creds.ClientID},
					"client_secret": {creds.Secret},
				})
				if err != nil {
					next(ctx)

					return
				}

				if err := json.Unmarshal(body, &res); err != nil || !res.Active {
					next(ctx)

					return
				}

				if results != nil {
					// Cache for min(remaining token lifetime, the configured cap).
					ttl := o.cacheTTL
					if res.ExpiresAt > 0 {
						if until := time.Until(time.Unix(res.ExpiresAt, 0)); until < ttl {
							ttl = until
						}
					}

					if ttl > 0 {
						_ = results.Set(ctx, tok, res, cache.TTL[auth.IntrospectionResponse](ttl))
					}
				}
			}

			if len(o.audiences) > 0 && !slices.Contains(o.audiences, res.Audience) && !slices.Contains(o.audiences, res.ClientID) {
				next(ctx)

				return
			}

			var jkt string
			if res.Confirmation != nil {
				jkt = res.Confirmation.JKT
			}

			if err := a.VerifyDPoPBinding(ctx, tok, jkt); err != nil {
				ctx.Error(err)

				return
			}

			info := auth.UserInfo{
				ID:       res.Subject,
				Name:     res.Username,
				Scope:    res.Scope,
				ClientID: res.ClientID,
			}
			ctx.SetUser(info.ToUser())

			next(ctx)
		}
	}
}
