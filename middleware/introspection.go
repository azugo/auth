package middleware

import (
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"azugo.io/auth"

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

// Introspection builds an Auth middleware for a detached resource server: opaque Bearer
// tokens are validated by POSTing them to the auth server's RFC 7662 introspection endpoint.
func Introspection(endpoint string, creds ClientCredentials, opts ...IntrospectionOption) azugo.RequestHandlerFunc {
	o := introspectionOptions{cacheTTL: 30 * time.Second}
	for _, opt := range opts {
		opt.apply(&o)
	}

	var (
		once    sync.Once
		results cache.Instance[auth.UserInfo]
	)

	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			tok, ok := strings.CutPrefix(ctx.Header.Get(http.HeaderAuthorization), "Bearer ")
			if !ok || tok == "" {
				next(ctx)

				return
			}

			if o.cacheTTL > 0 {
				once.Do(func() {
					results, _ = cache.Create[auth.UserInfo](ctx.App().Cache(), "auth:introspection", cache.MemoryCache)
				})

				if results != nil {
					if info, err := results.Get(ctx, tok); err == nil && info.ID != "" {
						ctx.SetUser(info.ToUser())
						next(ctx)

						return
					}
				}
			}

			body, err := ctx.HTTPClient().PostForm(endpoint, url.Values{
				"token":         {tok},
				"client_id":     {creds.ClientID},
				"client_secret": {creds.Secret},
			})
			if err != nil {
				next(ctx)

				return
			}

			var res auth.IntrospectionResponse
			if err := json.Unmarshal(body, &res); err != nil || !res.Active {
				next(ctx)

				return
			}

			if len(o.audiences) > 0 && !slices.Contains(o.audiences, res.Audience) && !slices.Contains(o.audiences, res.ClientID) {
				next(ctx)

				return
			}

			info := auth.UserInfo{
				ID:       res.Subject,
				Name:     res.Username,
				Scope:    res.Scope,
				ClientID: res.ClientID,
			}
			ctx.SetUser(info.ToUser())

			if results != nil {
				// Cache for min(remaining token lifetime, the configured cap).
				ttl := o.cacheTTL
				if res.ExpiresAt > 0 {
					if until := time.Until(time.Unix(res.ExpiresAt, 0)); until < ttl {
						ttl = until
					}
				}

				if ttl > 0 {
					_ = results.Set(ctx, tok, info, cache.TTL[auth.UserInfo](ttl))
				}
			}

			next(ctx)
		}
	}
}
