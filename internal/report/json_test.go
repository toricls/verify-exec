package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/toricls/verify-exec/internal/checks"
)

func TestJSONRendererSchemaAndSortOrder(t *testing.T) {
	var buf bytes.Buffer
	r := NewJSONRenderer(&buf)
	r.Init(nil)

	// Emit findings intentionally out of checkId order.
	findings := []checks.Finding{
		{CheckID: "TDEF-001", Level: checks.LevelError, Resource: "container/app", Message: "readonly", Remediation: "fix it"},
		{CheckID: "LOCAL-001", Level: checks.LevelOK, Resource: "local", Message: "plugin found"},
		{CheckID: "TASK-003", Level: checks.LevelOK, Resource: "container/b", Message: "agent running"},
		{CheckID: "TASK-003", Level: checks.LevelOK, Resource: "container/a", Message: "agent running"},
	}
	for _, f := range findings {
		r.Handle(FindingEmitted{Finding: f})
	}

	target := Target{Cluster: "my-cluster", TaskArn: "arn:aws:ecs:ap-northeast-1:123456789012:task/my-cluster/abc", Region: "ap-northeast-1"}
	if err := r.Close(Summarize(target, findings)); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	var doc struct {
		SchemaVersion string `json:"schemaVersion"`
		Target        struct {
			Cluster string `json:"cluster"`
			TaskArn string `json:"taskArn"`
			Region  string `json:"region"`
		} `json:"target"`
		Findings []struct {
			CheckID  string `json:"checkId"`
			Level    string `json:"level"`
			Resource string `json:"resource"`
		} `json:"findings"`
		Summary struct {
			OK      int `json:"ok"`
			Warn    int `json:"warn"`
			Error   int `json:"error"`
			Skip    int `json:"skip"`
			Unknown int `json:"unknown"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}

	if doc.SchemaVersion != "1" {
		t.Errorf("schemaVersion = %q, want \"1\"", doc.SchemaVersion)
	}
	if doc.Target.Cluster != "my-cluster" || doc.Target.Region != "ap-northeast-1" {
		t.Errorf("target = %+v", doc.Target)
	}

	wantOrder := []string{"LOCAL-001", "TASK-003", "TASK-003", "TDEF-001"}
	if len(doc.Findings) != len(wantOrder) {
		t.Fatalf("got %d findings, want %d", len(doc.Findings), len(wantOrder))
	}
	for i, f := range doc.Findings {
		if f.CheckID != wantOrder[i] {
			t.Errorf("findings[%d].checkId = %s, want %s", i, f.CheckID, wantOrder[i])
		}
	}
	// Secondary sort by resource within the same checkId.
	if doc.Findings[1].Resource != "container/a" || doc.Findings[2].Resource != "container/b" {
		t.Errorf("TASK-003 findings not sorted by resource: %+v", doc.Findings[1:3])
	}

	if doc.Summary.OK != 3 || doc.Summary.Error != 1 {
		t.Errorf("summary = %+v, want ok=3 error=1", doc.Summary)
	}
}
