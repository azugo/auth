package auth

import (
	"context"

	"azugo.io/core/cache"
)

// setSynced writes value and waits for it to be visible.
func setSynced[T any](ctx context.Context, c cache.Instance[T], key string, value T, opts ...cache.ItemOption[T]) error {
	if err := c.Set(ctx, key, value, opts...); err != nil {
		return err
	}

	return c.Sync(ctx)
}

// deleteSynced removes key and waits for the removal to be visible.
func deleteSynced[T any](ctx context.Context, c cache.Instance[T], key string) error {
	if err := c.Delete(ctx, key); err != nil {
		return err
	}

	return c.Sync(ctx)
}
