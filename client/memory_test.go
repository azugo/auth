package client

import (
	"context"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestMemoryRegistryGetClient(t *testing.T) {
	reg := NewMemoryRegistry(&Client{ID: "portal", Name: "Portal"})
	ctx := context.Background()

	got, err := reg.GetClient(ctx, "portal")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.Name, "Portal"))
	// An unset ResponseMode defaults to JSON.
	qt.Check(t, qt.Equals(got.ResponseMode, ResponseModeJSON))

	_, err = reg.GetClient(ctx, "unknown")
	qt.Check(t, qt.ErrorIs(err, ErrNotFound))
}

func TestMemoryRegistryPreservesExplicitResponseMode(t *testing.T) {
	reg := NewMemoryRegistry(&Client{ID: "ssr", ResponseMode: ResponseModeRedirect})

	got, err := reg.GetClient(context.Background(), "ssr")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.ResponseMode, ResponseModeRedirect))
}

func TestMemoryRegistryStoresCopy(t *testing.T) {
	c := &Client{ID: "portal", Name: "Portal"}
	reg := NewMemoryRegistry(c)

	c.Name = "Mutated"

	got, err := reg.GetClient(context.Background(), "portal")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.Name, "Portal"))
}
