// Package report renders check results. We ship PlainRenderer
// (append in completion order) and JSONRenderer (buffer everything,
// sort by checkId, emit once). The bubbletea TUI arrives later.
package report

import (
	"github.com/toricls/verify-exec/internal/checks"
)

type CheckMeta struct {
	ID   string
	Name string
}

// Event is the stream a Renderer consumes. Events are delivered
// serially (the runner funnels them through a single goroutine).
type Event interface{ isEvent() }

type CheckStarted struct{ Check CheckMeta }

type FindingEmitted struct{ Finding checks.Finding }

type CheckCompleted struct {
	Check    CheckMeta
	Findings []checks.Finding
}

func (CheckStarted) isEvent()   {}
func (FindingEmitted) isEvent() {}
func (CheckCompleted) isEvent() {}

type Target struct {
	Cluster string
	TaskArn string
	Region  string
}

type Summary struct {
	Target  Target
	OK      int
	Warn    int
	Error   int
	Skip    int
	Unknown int
}

func Summarize(target Target, findings []checks.Finding) Summary {
	s := Summary{Target: target}
	for _, f := range findings {
		switch f.Level {
		case checks.LevelOK:
			s.OK++
		case checks.LevelWarn:
			s.Warn++
		case checks.LevelError:
			s.Error++
		case checks.LevelSkip:
			s.Skip++
		case checks.LevelUnknown:
			s.Unknown++
		}
	}
	return s
}

type Renderer interface {
	Init(checks []CheckMeta) // full check list in registry order
	Handle(ev Event)
	Close(summary Summary) error
}

// Icon returns the TUI/plain icon for a level (catalog §1).
func Icon(l checks.Level) string {
	switch l {
	case checks.LevelOK:
		return "🟢"
	case checks.LevelWarn:
		return "🟡"
	case checks.LevelError:
		return "🔴"
	case checks.LevelSkip:
		return "⏭"
	case checks.LevelUnknown:
		return "❔"
	default:
		return "?"
	}
}
