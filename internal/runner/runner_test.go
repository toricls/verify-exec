package runner

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/toricls/verify-exec/internal/checks"
	"github.com/toricls/verify-exec/internal/collect"
	"github.com/toricls/verify-exec/internal/report"
)

type stubCheck struct {
	id       string
	deps     []collect.Field
	findings []checks.Finding
}

func (c *stubCheck) ID() string                        { return c.id }
func (c *stubCheck) Name() string                      { return c.id }
func (c *stubCheck) DependsOn() []collect.Field        { return c.deps }
func (c *stubCheck) Applicable(*collect.Snapshot) bool { return true }
func (c *stubCheck) Run(context.Context, *collect.Snapshot) []checks.Finding {
	return c.findings
}

func TestRunEmitsSkipWhenDependencyCanceledByFailFast(t *testing.T) {
	s := collect.NewSnapshot()
	// Simulate the stopped-task fail-fast: the dependency promise
	// resolves with the ErrTaskNotRunning cancellation cause.
	s.TaskDefinition.Complete(nil, collect.ErrTaskNotRunning)
	s.Task.Complete(&ecstypes.Task{TaskArn: aws.String("arn:x:task/abc")}, nil)

	check := &stubCheck{id: "TDEF-001", deps: []collect.Field{collect.FieldTaskDefinition}}
	findings, err := Run(context.Background(), Options{
		Checks:   []checks.Check{check},
		Snapshot: s,
		Renderer: report.NewPlainRenderer(&bytes.Buffer{}),
		TaskID:   "abc",
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Level != checks.LevelSkip {
		t.Fatalf("findings = %+v, want single skip", findings)
	}
}

func TestRunReportsCollectionFailureAsUnknownAndToolError(t *testing.T) {
	s := collect.NewSnapshot()
	collectErr := errors.New("AccessDenied")
	s.Task.Complete(nil, collectErr)
	s.TaskDefinition.Complete(nil, collectErr)

	check := &stubCheck{id: "TASK-002", deps: []collect.Field{collect.FieldTask}}
	findings, err := Run(context.Background(), Options{
		Checks:   []checks.Check{check},
		Snapshot: s,
		Renderer: report.NewPlainRenderer(&bytes.Buffer{}),
		TaskID:   "abc",
	})
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("Run() error = %v, want AccessDenied tool failure", err)
	}
	if len(findings) != 1 || findings[0].Level != checks.LevelUnknown {
		t.Fatalf("findings = %+v, want single unknown", findings)
	}
}

func TestRunFiltersFindingsByContainer(t *testing.T) {
	s := collect.NewSnapshot()
	s.Task.Complete(&ecstypes.Task{
		TaskArn: aws.String("arn:x:task/abc"),
		Containers: []ecstypes.Container{
			{Name: aws.String("app")},
			{Name: aws.String("sidecar")},
		},
	}, nil)
	s.TaskDefinition.Complete(&ecstypes.TaskDefinition{}, nil)

	check := &stubCheck{
		id:   "TASK-003",
		deps: []collect.Field{collect.FieldTask},
		findings: []checks.Finding{
			{CheckID: "TASK-003", Level: checks.LevelOK, Resource: "container/app"},
			{CheckID: "TASK-003", Level: checks.LevelError, Resource: "container/sidecar"},
			{CheckID: "TASK-003", Level: checks.LevelOK, Resource: "task/abc"},
		},
	}
	findings, err := Run(context.Background(), Options{
		Checks:    []checks.Check{check},
		Snapshot:  s,
		Renderer:  report.NewPlainRenderer(&bytes.Buffer{}),
		TaskID:    "abc",
		Container: "app",
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	// container/sidecar dropped; container/app and task-level kept.
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Resource == "container/sidecar" {
			t.Errorf("sidecar finding should have been filtered out")
		}
	}
}

func TestRunRejectsUnknownContainerFilter(t *testing.T) {
	s := collect.NewSnapshot()
	s.Task.Complete(&ecstypes.Task{
		TaskArn:    aws.String("arn:x:task/abc"),
		Containers: []ecstypes.Container{{Name: aws.String("app")}},
	}, nil)
	s.TaskDefinition.Complete(&ecstypes.TaskDefinition{}, nil)

	_, err := Run(context.Background(), Options{
		Checks:    []checks.Check{&stubCheck{id: "TASK-002", deps: []collect.Field{collect.FieldTask}}},
		Snapshot:  s,
		Renderer:  report.NewPlainRenderer(&bytes.Buffer{}),
		TaskID:    "abc",
		Container: "nope",
	})
	if err == nil || !strings.Contains(err.Error(), `container "nope" not found`) {
		t.Errorf("Run() error = %v, want unknown-container failure", err)
	}
}
