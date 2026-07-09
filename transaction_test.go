package auth

import (
	"context"
	"testing"

	"azugo.io/auth/client"
	"azugo.io/auth/session"

	"github.com/go-quicktest/qt"
)

func TestTransactionRun(t *testing.T) {
	ctx := context.Background()

	// Without a Transactor, fn runs directly.
	a, err := New(newApp(t), validConfig(), stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry())
	qt.Assert(t, qt.IsNil(err))

	ran := false
	qt.Assert(t, qt.IsNil(a.Transaction.Run(ctx, func(context.Context) error { ran = true; return nil })))
	qt.Check(t, qt.IsTrue(ran))

	// With a Transactor, fn runs inside the unit of work.
	wrapped := false
	tx := TransactorFunc(func(ctx context.Context, fn func(context.Context) error) error {
		wrapped = true
		return fn(ctx)
	})

	a2, err := New(newApp(t), validConfig(), stubUsers{}, session.NewMemoryStore(), client.NewMemoryRegistry(), Transactor(tx))
	qt.Assert(t, qt.IsNil(err))

	ran2 := false
	qt.Assert(t, qt.IsNil(a2.Transaction.Run(ctx, func(context.Context) error { ran2 = true; return nil })))
	qt.Check(t, qt.IsTrue(wrapped))
	qt.Check(t, qt.IsTrue(ran2))
}
