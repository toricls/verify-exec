// Package runner orchestrates check execution: it runs every check in
// its own goroutine, waits for declared Snapshot dependencies, converts
// dependency failures into skip/unknown findings, and streams events to
// a Renderer as each check completes, so the first results appear
// before collection has finished.
package runner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/toricls/verify-exec/internal/checks"
	"github.com/toricls/verify-exec/internal/collect"
	"github.com/toricls/verify-exec/internal/report"
)

type Options struct {
	Checks   []checks.Check
	Snapshot *collect.Snapshot
	Renderer report.Renderer
	// TaskID labels findings synthesized by the runner itself (skip /
	// unknown for unavailable dependencies).
	TaskID string
	// Container, when non-empty, limits container-granularity findings
	// to that container.
	Container string
}

// Run executes all checks and returns every emitted finding. The error
// return reports tool-level failures (collection errors, unknown
// --container) that must map to exit code 3; findings that were
// still produced are rendered regardless.
func Run(ctx context.Context, opts Options) ([]checks.Finding, error) {
	metas := make([]report.CheckMeta, 0, len(opts.Checks))
	for _, c := range opts.Checks {
		metas = append(metas, report.CheckMeta{ID: c.ID(), Name: c.Name()})
	}
	opts.Renderer.Init(metas)

	// Renderers are not required to be goroutine-safe: funnel all
	// events through one consumer.
	events := make(chan report.Event)
	renderDone := make(chan struct{})
	go func() {
		defer close(renderDone)
		for ev := range events {
			opts.Renderer.Handle(ev)
		}
	}()

	var (
		mu       sync.Mutex
		all      []checks.Finding
		toolErrs []error
	)
	// A single collection failure (e.g. expired credentials) surfaces
	// through every dependent check, and derived promises wrap the root
	// failure with %w; report each root cause once.
	recordToolErr := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		for _, seen := range toolErrs {
			if errors.Is(err, seen) || errors.Is(seen, err) {
				return
			}
		}
		toolErrs = append(toolErrs, err)
	}

	var wg sync.WaitGroup
	for _, c := range opts.Checks {
		wg.Add(1)
		go func(c checks.Check) {
			defer wg.Done()
			meta := report.CheckMeta{ID: c.ID(), Name: c.Name()}
			events <- report.CheckStarted{Check: meta}

			findings := runOne(ctx, c, opts, recordToolErr)
			findings = filterByContainer(findings, opts.Container)

			for _, f := range findings {
				events <- report.FindingEmitted{Finding: f}
			}
			events <- report.CheckCompleted{Check: meta, Findings: findings}

			mu.Lock()
			all = append(all, findings...)
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	close(events)
	<-renderDone

	if opts.Container != "" {
		if err := validateContainerFilter(ctx, opts.Snapshot, opts.Container); err != nil {
			toolErrs = append(toolErrs, err)
		}
	}
	return all, errors.Join(toolErrs...)
}

func runOne(ctx context.Context, c checks.Check, opts Options, recordToolErr func(error)) []checks.Finding {
	resource := "task/" + opts.TaskID

	for _, field := range c.DependsOn() {
		err := opts.Snapshot.Wait(ctx, field)
		if err == nil {
			continue
		}
		// Fail-fast cancellation (task stopped) → the check is skipped,
		// not failed.
		if errors.Is(err, collect.ErrTaskNotRunning) {
			return []checks.Finding{{
				CheckID:  c.ID(),
				Level:    checks.LevelSkip,
				Resource: resource,
				Message:  "skipped: task is not running",
			}}
		}
		// Anything else is a collection failure: the check result is
		// unknown and the run as a whole is a tool failure (exit 3).
		// The raw cause is recorded (without a check-ID prefix) so the
		// same root failure dedupes across dependent checks.
		recordToolErr(err)
		return []checks.Finding{{
			CheckID:  c.ID(),
			Level:    checks.LevelUnknown,
			Resource: resource,
			Message:  fmt.Sprintf("could not evaluate: %v", err),
		}}
	}

	if !c.Applicable(opts.Snapshot) {
		return []checks.Finding{{
			CheckID:  c.ID(),
			Level:    checks.LevelSkip,
			Resource: resource,
			Message:  "not applicable to this task",
		}}
	}
	return c.Run(ctx, opts.Snapshot)
}

func filterByContainer(findings []checks.Finding, container string) []checks.Finding {
	if container == "" {
		return findings
	}
	filtered := findings[:0]
	for _, f := range findings {
		name, isContainer := strings.CutPrefix(f.Resource, "container/")
		if isContainer && name != container {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

// validateContainerFilter reports an unknown --container value as a
// tool failure. Called after all checks completed, so the Task promise
// is already settled and Get does not block.
func validateContainerFilter(ctx context.Context, s *collect.Snapshot, container string) error {
	task, err := s.Task.Get(ctx)
	if err != nil {
		return nil // the collection failure itself is already reported
	}
	names := make([]string, 0, len(task.Containers))
	for _, c := range task.Containers {
		name := aws.ToString(c.Name)
		if name == container {
			return nil
		}
		names = append(names, name)
	}
	return fmt.Errorf("container %q not found in task (available: %s)", container, strings.Join(names, ", "))
}
