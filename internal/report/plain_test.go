package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/toricls/verify-exec/internal/checks"
)

func TestPlainRendererAppendsPerFinding(t *testing.T) {
	var buf bytes.Buffer
	r := NewPlainRenderer(&buf)
	r.Init(nil)

	r.Handle(CheckStarted{Check: CheckMeta{ID: "TASK-002", Name: "Execute command enabled"}})
	r.Handle(CheckCompleted{
		Check: CheckMeta{ID: "TASK-002", Name: "Execute command enabled"},
		Findings: []checks.Finding{{
			CheckID: "TASK-002", Level: checks.LevelError,
			Resource: "task/abc", Message: "enableExecuteCommand is false on this task",
			Remediation: "Re-run the task with --enable-execute-command",
		}},
	})
	if err := r.Close(Summary{Error: 1}); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"🔴 TASK-002",
		"task/abc — enableExecuteCommand is false",
		"↳ Re-run the task with --enable-execute-command",
		"Summary: 0 ok, 0 warn, 1 error, 0 skip, 0 unknown",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// ok findings must not print their remediation; started events print nothing.
	if strings.Count(out, "TASK-002") != 1 {
		t.Errorf("check line should appear exactly once:\n%s", out)
	}
}

func TestPlainRendererOmitsRemediationForOK(t *testing.T) {
	var buf bytes.Buffer
	r := NewPlainRenderer(&buf)
	r.Handle(CheckCompleted{
		Check: CheckMeta{ID: "TASK-001", Name: "Task is running"},
		Findings: []checks.Finding{{
			CheckID: "TASK-001", Level: checks.LevelOK,
			Resource: "task/abc", Message: "task is RUNNING",
			Remediation: "should not appear",
		}},
	})
	if strings.Contains(buf.String(), "should not appear") {
		t.Errorf("ok finding printed remediation:\n%s", buf.String())
	}
}
