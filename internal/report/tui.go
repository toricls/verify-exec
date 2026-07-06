package report

import (
	"fmt"
	"io"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-runewidth"

	"github.com/toricls/verify-exec/internal/checks"
)

// TUIRenderer renders checks as a live-updating fixed-row list: every
// check appears in registry order and its row updates ⏳ → 🟢/🟡/🔴 as
// results arrive. It deliberately avoids the alt-screen so the final
// view stays in the terminal scrollback after exit.
type TUIRenderer struct {
	w io.Writer
	// cancelRun aborts the whole run when the user interrupts the TUI
	// (ctrl+c / q); collectors and checks then wind down quickly.
	cancelRun func()

	prog     *tea.Program
	progDone chan struct{}
	progErr  error
}

func NewTUIRenderer(w io.Writer, cancelRun func()) *TUIRenderer {
	return &TUIRenderer{w: w, cancelRun: cancelRun}
}

func (r *TUIRenderer) Init(metas []CheckMeta) {
	model := newTUIModel(metas, r.cancelRun)
	r.prog = tea.NewProgram(model, tea.WithOutput(r.w))
	r.progDone = make(chan struct{})
	go func() {
		_, err := r.prog.Run()
		r.progErr = err
		close(r.progDone)
	}()
}

func (r *TUIRenderer) Handle(ev Event) {
	// Send is a no-op once the program has quit (e.g. user interrupt),
	// so late events from still-running checks are dropped safely.
	r.prog.Send(eventMsg{ev})
}

func (r *TUIRenderer) Close(summary Summary) error {
	r.prog.Send(summaryMsg{summary})
	<-r.progDone
	return r.progErr
}

type eventMsg struct{ ev Event }

type summaryMsg struct{ summary Summary }

type tuiRow struct {
	meta      CheckMeta
	completed bool
	findings  []checks.Finding
}

type tuiModel struct {
	rows        []tuiRow
	rowIndex    map[string]int
	width       int
	summary     *Summary
	interrupted bool
	cancelRun   func()
}

func newTUIModel(metas []CheckMeta, cancelRun func()) *tuiModel {
	m := &tuiModel{
		rows:      make([]tuiRow, len(metas)),
		rowIndex:  make(map[string]int, len(metas)),
		cancelRun: cancelRun,
	}
	for i, meta := range metas {
		m.rows[i] = tuiRow{meta: meta}
		m.rowIndex[meta.ID] = i
	}
	return m
}

func (m *tuiModel) Init() tea.Cmd { return nil }

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.interrupted = true
			if m.cancelRun != nil {
				m.cancelRun()
			}
			return m, tea.Quit
		}
	case eventMsg:
		if completed, ok := msg.ev.(CheckCompleted); ok {
			if i, ok := m.rowIndex[completed.Check.ID]; ok {
				m.rows[i].completed = true
				m.rows[i].findings = completed.Findings
			}
		}
	case summaryMsg:
		summary := msg.summary
		m.summary = &summary
		return m, tea.Quit
	}
	return m, nil
}

func (m *tuiModel) View() string {
	done := m.summary != nil
	var b strings.Builder
	for _, row := range m.rows {
		m.renderRow(&b, row, done)
	}
	switch {
	case m.interrupted:
		b.WriteString("\nInterrupted.\n")
	case done:
		fmt.Fprintf(&b, "\nSummary: %d ok, %d warn, %d error, %d skip, %d unknown\n",
			m.summary.OK, m.summary.Warn, m.summary.Error, m.summary.Skip, m.summary.Unknown)
	}
	return b.String()
}

// renderRow writes the fixed row for one check: a pending marker, a
// single-line result, or a parent line with per-finding child rows
// (container granularity). Remediations are added only to the final
// view (once done) to keep the live view compact.
func (m *tuiModel) renderRow(b *strings.Builder, row tuiRow, done bool) {
	label := row.meta.ID + "  " + row.meta.Name
	switch {
	case !row.completed:
		m.line(b, 0, "⏳", label, "")
	case len(row.findings) == 1:
		f := row.findings[0]
		m.line(b, 0, Icon(f.Level), label, fmt.Sprintf("%s — %s", f.Resource, f.Message))
		m.remediation(b, f, done, 1)
	default:
		m.line(b, 0, Icon(worstLevel(row.findings)), label, "")
		for _, f := range row.findings {
			m.line(b, 1, Icon(f.Level), f.Resource, f.Message)
			m.remediation(b, f, done, 2)
		}
	}
}

func (m *tuiModel) remediation(b *strings.Builder, f checks.Finding, done bool, indent int) {
	if done && f.Remediation != "" && f.Level != checks.LevelOK {
		m.line(b, indent, "↳", f.Remediation, "")
	}
}

func (m *tuiModel) line(b *strings.Builder, indent int, icon, text, detail string) {
	line := strings.Repeat("   ", indent) + icon + " " + text
	if detail != "" {
		line += "  " + detail
	}
	// Keep every row on a single terminal line: wrapped lines would
	// corrupt the inline repaint. Emoji are double-width, hence the
	// small safety margin.
	if m.width > 2 {
		line = runewidth.Truncate(line, m.width-2, "…")
	}
	b.WriteString(line + "\n")
}

var levelSeverity = map[checks.Level]int{
	checks.LevelError:   4,
	checks.LevelWarn:    3,
	checks.LevelUnknown: 2,
	checks.LevelSkip:    1,
	checks.LevelOK:      0,
}

func worstLevel(findings []checks.Finding) checks.Level {
	worst := checks.LevelOK
	for _, f := range findings {
		if levelSeverity[f.Level] > levelSeverity[worst] {
			worst = f.Level
		}
	}
	return worst
}
