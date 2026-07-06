package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/toricls/verify-exec/internal/collect"
)

// TDEF-004: no container defines AWS credential environment variables,
// which would pollute the SSM agent's credential chain and can break
// or hijack the exec session's identity.
type tdef004 struct{}

func NewTdef004() Check { return &tdef004{} }

func (c *tdef004) ID() string   { return "TDEF-004" }
func (c *tdef004) Name() string { return "No AWS credential env vars" }
func (c *tdef004) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldTaskDefinition}
}
func (c *tdef004) Applicable(s *collect.Snapshot) bool { return true }

var credentialEnvVars = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY"}

func (c *tdef004) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	taskDef := resolved(s.TaskDefinition)

	var findings []Finding
	for _, cd := range taskDef.ContainerDefinitions {
		name := aws.ToString(cd.Name)
		var defined []string
		for _, env := range cd.Environment {
			envName := aws.ToString(env.Name)
			for _, credential := range credentialEnvVars {
				if envName == credential {
					defined = append(defined, envName)
				}
			}
		}
		if len(defined) > 0 {
			findings = append(findings, Finding{
				CheckID:  c.ID(),
				Level:    LevelWarn,
				Resource: containerResource(name),
				Message:  fmt.Sprintf("container defines %s; static credentials shadow the task role and can break the SSM agent's credential chain", strings.Join(defined, ", ")),
				Remediation: "Remove static AWS credentials from the container environment and rely on the task role. " +
					docTroubleshooting,
			})
		} else {
			findings = append(findings, Finding{
				CheckID:  c.ID(),
				Level:    LevelOK,
				Resource: containerResource(name),
				Message:  "no AWS credential environment variables defined",
			})
		}
	}
	return findings
}
