package contract

import "context"

// ClaimMapper turns the raw claims returned by an external IdP or a passwordless
// authenticator into a UserInfo.
type ClaimMapper interface {
	MapClaims(ctx context.Context, name string, raw map[string]any) (UserInfo, error)
}

// ClaimMapperFunc adapts a plain function to the ClaimMapper interface.
type ClaimMapperFunc func(ctx context.Context, name string, raw map[string]any) (UserInfo, error)

// MapClaims implements ClaimMapper.
func (f ClaimMapperFunc) MapClaims(ctx context.Context, name string, raw map[string]any) (UserInfo, error) {
	return f(ctx, name, raw)
}
