package checks

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/toricls/verify-exec/internal/collect"
)

func snapshotWithTask(task *ecstypes.Task) *collect.Snapshot {
	s := collect.NewSnapshot()
	s.Task.Complete(task, nil)
	return s
}

func snapshotWithTaskDef(td *ecstypes.TaskDefinition) *collect.Snapshot {
	s := collect.NewSnapshot()
	s.TaskDefinition.Complete(td, nil)
	return s
}

const taskArn = "arn:aws:ecs:ap-northeast-1:123456789012:task/my-cluster/abc123"

func TestTask001(t *testing.T) {
	tests := []struct {
		name      string
		status    string
		stopped   string
		wantLevel Level
	}{
		{"running", "RUNNING", "", LevelOK},
		{"pending", "PENDING", "", LevelWarn},
		{"provisioning", "PROVISIONING", "", LevelWarn},
		{"stopped", "STOPPED", "Essential container exited", LevelError},
		{"deactivating", "DEACTIVATING", "", LevelError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &ecstypes.Task{
				TaskArn:    aws.String(taskArn),
				LastStatus: aws.String(tt.status),
			}
			if tt.stopped != "" {
				task.StoppedReason = aws.String(tt.stopped)
			}
			findings := NewTask001().Run(context.Background(), snapshotWithTask(task))
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			f := findings[0]
			if f.Level != tt.wantLevel {
				t.Errorf("level = %s, want %s", f.Level, tt.wantLevel)
			}
			if f.Resource != "task/abc123" {
				t.Errorf("resource = %q, want task/abc123", f.Resource)
			}
		})
	}
}

func TestTask002(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		task := &ecstypes.Task{
			TaskArn:              aws.String(taskArn),
			EnableExecuteCommand: enabled,
		}
		findings := NewTask002().Run(context.Background(), snapshotWithTask(task))
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		want := LevelError
		if enabled {
			want = LevelOK
		}
		if findings[0].Level != want {
			t.Errorf("enabled=%v: level = %s, want %s", enabled, findings[0].Level, want)
		}
	}
}

func TestTask003PerContainer(t *testing.T) {
	task := &ecstypes.Task{
		TaskArn:    aws.String(taskArn),
		LastStatus: aws.String("RUNNING"),
		Containers: []ecstypes.Container{
			{
				Name: aws.String("app"),
				ManagedAgents: []ecstypes.ManagedAgent{{
					Name:       ecstypes.ManagedAgentNameExecuteCommandAgent,
					LastStatus: aws.String("RUNNING"),
				}},
			},
			{
				Name: aws.String("sidecar"),
				ManagedAgents: []ecstypes.ManagedAgent{{
					Name:       ecstypes.ManagedAgentNameExecuteCommandAgent,
					LastStatus: aws.String("STOPPED"),
					Reason:     aws.String("agent exited"),
				}},
			},
			{Name: aws.String("no-agent")},
		},
	}
	findings := NewTask003().Run(context.Background(), snapshotWithTask(task))
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}

	byResource := map[string]Finding{}
	for _, f := range findings {
		byResource[f.Resource] = f
	}
	if f := byResource["container/app"]; f.Level != LevelOK {
		t.Errorf("app: level = %s, want ok", f.Level)
	}
	if f := byResource["container/sidecar"]; f.Level != LevelError {
		t.Errorf("sidecar: level = %s, want error", f.Level)
	}
	if f := byResource["container/no-agent"]; f.Level != LevelError {
		t.Errorf("no-agent: level = %s, want error", f.Level)
	}
}

func TestTask003SkipsWhenTaskNotRunning(t *testing.T) {
	task := &ecstypes.Task{
		TaskArn:    aws.String(taskArn),
		LastStatus: aws.String("STOPPED"),
		Containers: []ecstypes.Container{{Name: aws.String("app")}},
	}
	findings := NewTask003().Run(context.Background(), snapshotWithTask(task))
	if len(findings) != 1 || findings[0].Level != LevelSkip {
		t.Fatalf("findings = %+v, want single skip", findings)
	}
}

func TestTdef001PerContainer(t *testing.T) {
	td := &ecstypes.TaskDefinition{
		ContainerDefinitions: []ecstypes.ContainerDefinition{
			{Name: aws.String("app"), ReadonlyRootFilesystem: aws.Bool(true)},
			{Name: aws.String("sidecar"), ReadonlyRootFilesystem: aws.Bool(false)},
			{Name: aws.String("unset")},
		},
	}
	findings := NewTdef001().Run(context.Background(), snapshotWithTaskDef(td))
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}

	byResource := map[string]Finding{}
	for _, f := range findings {
		byResource[f.Resource] = f
	}
	if f := byResource["container/app"]; f.Level != LevelError {
		t.Errorf("app: level = %s, want error", f.Level)
	}
	if f := byResource["container/sidecar"]; f.Level != LevelOK {
		t.Errorf("sidecar: level = %s, want ok", f.Level)
	}
	if f := byResource["container/unset"]; f.Level != LevelOK {
		t.Errorf("unset: level = %s, want ok", f.Level)
	}
}

func TestRegistryOrderAndIDs(t *testing.T) {
	want := []string{"LOCAL-001", "LOCAL-002", "TASK-001", "TASK-002", "TASK-003", "TDEF-001"}
	all := All()
	if len(all) != len(want) {
		t.Fatalf("got %d checks, want %d", len(all), len(want))
	}
	for i, c := range all {
		if c.ID() != want[i] {
			t.Errorf("check[%d].ID() = %s, want %s", i, c.ID(), want[i])
		}
	}
}
