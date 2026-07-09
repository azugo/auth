package auth

import (
	"context"
)

// TransactionCtx provides multi-write transaction helpers.
type TransactionCtx struct {
	noCopy noCopy

	tx TxRunner
}

// Run executes function inside the transaction.
func (c *TransactionCtx) Run(ctx context.Context, fn func(ctx context.Context) error) error {
	if c.tx == nil {
		return fn(ctx)
	}

	return c.tx.RunInTx(ctx, fn)
}
