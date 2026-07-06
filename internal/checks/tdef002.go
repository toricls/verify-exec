package checks

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/toricls/verify-exec/internal/collect"
)

// TDEF-002: linuxParameters.initProcessEnabled is true on each
// container, so exec sessions do not leave zombie processes behind.
type tdef002 struct{}

func NewTdef002() Check { return &tdef002{} }

func (c *tdef002) ID() string   { return "TDEF-002" }
func (c *tdef002) Name() string { return "Init process enabled" }
func (c *tdef002) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldTaskDefinition}
}

func (c *tdef002) Applicable(s *collect.Snapshot) bool {
	return !isWindowsTaskDef(resolved(s.TaskDefinition))
}

func (c *tdef002) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	taskDef := resolved(s.TaskDefinition)

	var findings []Finding
	for _, cd := range taskDef.ContainerDefinitions {
		name := aws.ToString(cd.Name)
		enabled := cd.LinuxParameters != nil && aws.ToBool(cd.LinuxParameters.InitProcessEnabled)
		if enabled {
			findings = append(findings, Finding{
				CheckID:  c.ID(),
				Level:    LevelOK,
				Resource: containerResource(name),
				Message:  "initProcessEnabled is true",
			})
		} else {
			findings = append(findings, Finding{
				CheckID:  c.ID(),
				Level:    LevelWarn,
				Resource: containerResource(name),
				Message:  "initProcessEnabled is not set; exec sessions may leave zombie processes",
				Remediation: "Set linuxParameters.initProcessEnabled=true in the container definition. " +
					docExec + "#ecs-exec-considerations",
			})
		}
	}
	return findings
}
