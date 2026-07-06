package collect

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPromiseGetReturnsCompletedValue(t *testing.T) {
	p := NewPromise[string]()
	go p.Complete("hello", nil)

	got, err := p.Get(context.Background())
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got != "hello" {
		t.Errorf("Get() = %q, want %q", got, "hello")
	}
}

func TestPromiseGetReturnsCompletedError(t *testing.T) {
	p := NewPromise[string]()
	wantErr := errors.New("boom")
	p.Complete("", wantErr)

	if _, err := p.Get(context.Background()); !errors.Is(err, wantErr) {
		t.Errorf("Get() error = %v, want %v", err, wantErr)
	}
}

func TestPromiseFirstCompleteWins(t *testing.T) {
	p := NewPromise[int]()
	p.Complete(1, nil)
	p.Complete(2, nil)

	if got, _ := p.Get(context.Background()); got != 1 {
		t.Errorf("Get() = %d, want 1", got)
	}
}

func TestPromiseGetReturnsCancelCause(t *testing.T) {
	p := NewPromise[int]()
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(ErrTaskNotRunning)

	if _, err := p.Get(ctx); !errors.Is(err, ErrTaskNotRunning) {
		t.Errorf("Get() error = %v, want ErrTaskNotRunning", err)
	}
}

func TestPromiseGetBlocksUntilComplete(t *testing.T) {
	p := NewPromise[int]()
	go func() {
		time.Sleep(10 * time.Millisecond)
		p.Complete(42, nil)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := p.Get(ctx)
	if err != nil || got != 42 {
		t.Errorf("Get() = (%d, %v), want (42, nil)", got, err)
	}
}
