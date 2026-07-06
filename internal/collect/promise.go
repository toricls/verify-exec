// Package collect implements the data-collection side of the checker:
// a Promise-based Snapshot whose fields are resolved concurrently by
// collector goroutines. Checks never call AWS APIs directly; they wait
// on Snapshot promises instead, which deduplicates API calls, keeps
// checks testable as pure functions, and lets each check report as
// soon as its own dependencies resolve.
package collect

import (
	"context"
	"sync"
)

// Promise is a write-once container for a value resolved asynchronously.
// Complete may be called multiple times but only the first call wins.
type Promise[T any] struct {
	once sync.Once
	done chan struct{}
	val  T
	err  error
}

func NewPromise[T any]() *Promise[T] {
	return &Promise[T]{done: make(chan struct{})}
}

// Complete resolves the promise with a value or an error.
func (p *Promise[T]) Complete(val T, err error) {
	p.once.Do(func() {
		p.val = val
		p.err = err
		close(p.done)
	})
}

// Get blocks until the promise is resolved or ctx is done. When ctx is
// canceled via context.CancelCause, the cause is returned (used for the
// fail-fast skip semantics when the task turns out to be stopped).
func (p *Promise[T]) Get(ctx context.Context) (T, error) {
	select {
	case <-p.done:
		return p.val, p.err
	case <-ctx.Done():
		var zero T
		return zero, context.Cause(ctx)
	}
}
