package report

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/toricls/verify-exec/internal/checks"
)

func testMetas() []CheckMeta {
	return []CheckMeta{
		{ID: "LOCAL-001", Name: "Session Manager Plugin installed"},
		{ID: "TASK-003", Name: "ExecuteCommandAgent running"},
		{ID: "TDEF-001", Name: "Writable root filesystem"},
	}
}

func viewOf(t *testing.T, m tea.Model) string {
	t.Helper()
	return m.(*tuiModel).View()
}

func TestTUIModelShowsAllChecksPendingInRegistryOrder(t *testing.T) {
	m := newTUIModel(testMetas(), nil)
	view := m.View()

	lines := strings.Split(strings.TrimRight(view, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), view)
	}
	for i, id := range []string{"LOCAL-001", "TASK-003", "TDEF-001"} {
		if !strings.Contains(lines[i], "⏳") || !strings.Contains(lines[i], id) {
			t.Errorf("line %d = %q, want pending %s", i, lines[i], id)
		}
	}
}

func TestTUIModelUpdatesRowInPlace(t *testing.T) {
	var m tea.Model = newTUIModel(testMetas(), nil)
	m, _ = m.Update(eventMsg{CheckCompleted{
		Check: CheckMeta{ID: "TDEF-001", Name: "Writable root filesystem"},
		Findings: []checks.Finding{{
			CheckID: "TDEF-001", Level: checks.LevelOK,
			Resource: "container/app", Message: "readonlyRootFilesystem is not enabled",
		}},
	}})

	lines := strings.Split(strings.TrimRight(viewOf(t, m), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3 (fixed rows):\n%s", len(lines), viewOf(t, m))
	}
	// Registry order is preserved: TDEF-001 stays on the last row.
	if !strings.Contains(lines[2], "🟢") || !strings.Contains(lines[2], "TDEF-001") {
		t.Errorf("line 3 = %q, want completed TDEF-001", lines[2])
	}
	if !strings.Contains(lines[0], "⏳") {
		t.Errorf("line 1 = %q, want still pending", lines[0])
	}
}

func TestTUIModelExpandsContainerChildRows(t *testing.T) {
	var m tea.Model = newTUIModel(testMetas(), nil)
	m, _ = m.Update(eventMsg{CheckCompleted{
		Check: CheckMeta{ID: "TASK-003", Name: "ExecuteCommandAgent running"},
		Findings: []checks.Finding{
			{CheckID: "TASK-003", Level: checks.LevelOK, Resource: "container/app", Message: "ExecuteCommandAgent is RUNNING"},
			{CheckID: "TASK-003", Level: checks.LevelError, Resource: "container/sidecar", Message: "ExecuteCommandAgent is STOPPED", Remediation: "see docs"},
		},
	}})

	view := viewOf(t, m)
	lines := strings.Split(strings.TrimRight(view, "\n"), "\n")
	if len(lines) != 5 { // 2 pending + parent + 2 children
		t.Fatalf("got %d lines, want 5:\n%s", len(lines), view)
	}
	// The parent row aggregates to the worst child level.
	if !strings.Contains(lines[1], "🔴") || !strings.Contains(lines[1], "TASK-003") {
		t.Errorf("parent = %q, want 🔴 TASK-003", lines[1])
	}
	if !strings.Contains(lines[2], "container/app") || !strings.Contains(lines[3], "container/sidecar") {
		t.Errorf("children = %q / %q, want per-container rows", lines[2], lines[3])
	}
	// Remediation is deferred to the final (done) view.
	if strings.Contains(view, "see docs") {
		t.Errorf("live view must not include remediation:\n%s", view)
	}
}

func TestTUIModelFinalViewHasSummaryAndRemediation(t *testing.T) {
	var m tea.Model = newTUIModel(testMetas(), nil)
	m, _ = m.Update(eventMsg{CheckCompleted{
		Check: CheckMeta{ID: "TASK-003", Name: "ExecuteCommandAgent running"},
		Findings: []checks.Finding{{
			CheckID: "TASK-003", Level: checks.LevelError,
			Resource: "container/app", Message: "ExecuteCommandAgent is STOPPED", Remediation: "see docs",
		}},
	}})
	var cmd tea.Cmd
	m, cmd = m.Update(summaryMsg{Summary{Error: 1, OK: 2}})
	if cmd == nil {
		t.Fatal("summaryMsg must quit the program")
	}

	view := viewOf(t, m)
	if !strings.Contains(view, "Summary: 2 ok, 0 warn, 1 error, 0 skip, 0 unknown") {
		t.Errorf("final view missing summary:\n%s", view)
	}
	if !strings.Contains(view, "see docs") {
		t.Errorf("final view missing remediation:\n%s", view)
	}
}

func TestTUIModelInterruptCancelsRun(t *testing.T) {
	canceled := false
	var m tea.Model = newTUIModel(testMetas(), func() { canceled = true })
	m, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if !canceled {
		t.Error("ctrl+c must cancel the run")
	}
	if cmd == nil {
		t.Error("ctrl+c must quit the program")
	}
	if !strings.Contains(viewOf(t, m), "Interrupted.") {
		t.Errorf("view = %q, want interrupt notice", viewOf(t, m))
	}
}

func TestTUIModelTruncatesToWidth(t *testing.T) {
	var m tea.Model = newTUIModel(testMetas(), nil)
	m, _ = m.Update(tea.WindowSizeMsg{Width: 30, Height: 20})
	m, _ = m.Update(eventMsg{CheckCompleted{
		Check: CheckMeta{ID: "LOCAL-001", Name: "Session Manager Plugin installed"},
		Findings: []checks.Finding{{
			CheckID: "LOCAL-001", Level: checks.LevelOK, Resource: "local",
			Message: strings.Repeat("long message ", 20),
		}},
	}})
	for _, line := range strings.Split(strings.TrimRight(viewOf(t, m), "\n"), "\n") {
		if len([]rune(line)) > 30 {
			t.Errorf("line exceeds width: %q", line)
		}
	}
}

func TestWorstLevel(t *testing.T) {
	findings := []checks.Finding{
		{Level: checks.LevelOK},
		{Level: checks.LevelUnknown},
		{Level: checks.LevelWarn},
	}
	if got := worstLevel(findings); got != checks.LevelWarn {
		t.Errorf("worstLevel = %s, want warn", got)
	}
	findings = append(findings, checks.Finding{Level: checks.LevelError})
	if got := worstLevel(findings); got != checks.LevelError {
		t.Errorf("worstLevel = %s, want error", got)
	}
}
