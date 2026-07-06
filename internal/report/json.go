package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/toricls/verify-exec/internal/checks"
)

// JSONRenderer buffers all findings and emits a single document at
// Close, sorted by checkId to keep the output deterministic despite
// the nondeterministic completion order of parallel checks.
type JSONRenderer struct {
	w        io.Writer
	findings []checks.Finding
}

func NewJSONRenderer(w io.Writer) *JSONRenderer {
	return &JSONRenderer{w: w}
}

func (r *JSONRenderer) Init(checks []CheckMeta) {}

func (r *JSONRenderer) Handle(ev Event) {
	if e, ok := ev.(FindingEmitted); ok {
		r.findings = append(r.findings, e.Finding)
	}
}

type jsonFinding struct {
	CheckID     string `json:"checkId"`
	Level       string `json:"level"`
	Resource    string `json:"resource"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

type jsonTarget struct {
	Cluster string `json:"cluster"`
	TaskArn string `json:"taskArn"`
	Region  string `json:"region"`
}

type jsonSummary struct {
	OK      int `json:"ok"`
	Warn    int `json:"warn"`
	Error   int `json:"error"`
	Skip    int `json:"skip"`
	Unknown int `json:"unknown"`
}

type jsonDocument struct {
	SchemaVersion string        `json:"schemaVersion"`
	Target        jsonTarget    `json:"target"`
	Findings      []jsonFinding `json:"findings"`
	Summary       jsonSummary   `json:"summary"`
}

func (r *JSONRenderer) Close(summary Summary) error {
	sorted := make([]checks.Finding, len(r.findings))
	copy(sorted, r.findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].CheckID != sorted[j].CheckID {
			return sorted[i].CheckID < sorted[j].CheckID
		}
		return sorted[i].Resource < sorted[j].Resource
	})

	doc := jsonDocument{
		SchemaVersion: "1",
		Target: jsonTarget{
			Cluster: summary.Target.Cluster,
			TaskArn: summary.Target.TaskArn,
			Region:  summary.Target.Region,
		},
		Findings: make([]jsonFinding, 0, len(sorted)),
		Summary: jsonSummary{
			OK:      summary.OK,
			Warn:    summary.Warn,
			Error:   summary.Error,
			Skip:    summary.Skip,
			Unknown: summary.Unknown,
		},
	}
	for _, f := range sorted {
		doc.Findings = append(doc.Findings, jsonFinding{
			CheckID:     f.CheckID,
			Level:       string(f.Level),
			Resource:    f.Resource,
			Message:     f.Message,
			Remediation: f.Remediation,
		})
	}

	enc := json.NewEncoder(r.w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
