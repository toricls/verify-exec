// Package checks implements the check catalog. One check = one file,
// registered in catalog order via registry.go. Checks are pure with
// respect to AWS: they only read resolved Snapshot promises.
package checks

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/toricls/verify-exec/internal/collect"
)

// Level is the 5-value check result level. skip ("not evaluated") and
// unknown ("cannot be determined") are deliberately distinct from
// error/warn so that inconclusive results are never treated as failures.
type Level string

const (
	LevelOK      Level = "ok"
	LevelWarn    Level = "warn"
	LevelError   Level = "error"
	LevelSkip    Level = "skip"
	LevelUnknown Level = "unknown"
)

type Finding struct {
	CheckID     string
	Level       Level
	Resource    string // "container/<name>" | "task/<id>" | "cluster/<name>" | "local"
	Message     string
	Remediation string
}

type Check interface {
	ID() string // matches the catalog ID exactly (e.g. "TDEF-001")
	Name() string
	DependsOn() []collect.Field
	Applicable(s *collect.Snapshot) bool
	Run(ctx context.Context, s *collect.Snapshot) []Finding
}

const (
	docExec            = "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html"
	docTroubleshooting = "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec-troubleshooting.html"
)

// taskResource renders the "task/<id>" resource label from a task ARN.
func taskResource(t *ecstypes.Task) string {
	arn := aws.ToString(t.TaskArn)
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return "task/" + arn[i+1:]
	}
	return "task/" + arn
}

func containerResource(name string) string {
	return "container/" + name
}
