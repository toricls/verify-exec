package report

import (
	"fmt"
	"io"

	"github.com/toricls/verify-exec/internal/checks"
)

// PlainRenderer appends one line per finding as each check completes
// (completion order). It is the non-TTY fallback mode; on a TTY the
// TUI takes over later.
type PlainRenderer struct {
	w io.Writer
}

func NewPlainRenderer(w io.Writer) *PlainRenderer {
	return &PlainRenderer{w: w}
}

func (r *PlainRenderer) Init(checks []CheckMeta) {}

func (r *PlainRenderer) Handle(ev Event) {
	completed, ok := ev.(CheckCompleted)
	if !ok {
		return
	}
	for _, f := range completed.Findings {
		fmt.Fprintf(r.w, "%s %s  %s  %s — %s\n",
			Icon(f.Level), f.CheckID, completed.Check.Name, f.Resource, f.Message)
		if f.Remediation != "" && f.Level != checks.LevelOK {
			fmt.Fprintf(r.w, "   ↳ %s\n", f.Remediation)
		}
	}
}

func (r *PlainRenderer) Close(summary Summary) error {
	_, err := fmt.Fprintf(r.w, "\nSummary: %d ok, %d warn, %d error, %d skip, %d unknown\n",
		summary.OK, summary.Warn, summary.Error, summary.Skip, summary.Unknown)
	return err
}
