package checks

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/toricls/verify-exec/internal/collect"
)

// TDEF-001: readonlyRootFilesystem must not be true on any container.
// Emits one finding per container since the setting differs per
// container.
type tdef001 struct{}

func NewTdef001() Check { return &tdef001{} }

func (c *tdef001) ID() string   { return "TDEF-001" }
func (c *tdef001) Name() string { return "Writable root filesystem" }
func (c *tdef001) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldTaskDefinition}
}
func (c *tdef001) Applicable(s *collect.Snapshot) bool { return true }

func (c *tdef001) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	taskDef, err := s.TaskDefinition.Get(ctx)
	if err != nil {
		return nil
	}

	var findings []Finding
	for _, cd := range taskDef.ContainerDefinitions {
		name := aws.ToString(cd.Name)
		if aws.ToBool(cd.ReadonlyRootFilesystem) {
			findings = append(findings, Finding{
				CheckID:  c.ID(),
				Level:    LevelError,
				Resource: containerResource(name),
				Message:  "readonlyRootFilesystem is true; SSM agent cannot write required files",
				Remediation: "Set readonlyRootFilesystem=false in the task definition. " +
					docExec + "#ecs-exec-considerations",
			})
		} else {
			findings = append(findings, Finding{
				CheckID:  c.ID(),
				Level:    LevelOK,
				Resource: containerResource(name),
				Message:  "readonlyRootFilesystem is not enabled",
			})
		}
	}
	return findings
}
