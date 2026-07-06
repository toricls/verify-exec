package checks

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/toricls/verify-exec/internal/collect"
)

// TASK-005: the ECS container agent supports ECS Exec
// (>= 1.50.2, or >= 1.56 on Windows AMIs).
type task005 struct{}

func NewTask005() Check { return &task005{} }

func (c *task005) ID() string   { return "TASK-005" }
func (c *task005) Name() string { return "ECS container agent version" }
func (c *task005) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldTask, collect.FieldContainerInstance}
}

func (c *task005) Applicable(s *collect.Snapshot) bool {
	return isEC2OrExternal(resolved(s.Task))
}

func (c *task005) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	ci := resolved(s.ContainerInstance)
	if ci == nil {
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: taskResource(resolved(s.Task)),
			Message:  "no container instance data available",
		}}
	}
	resource := "instance/" + aws.ToString(ci.Ec2InstanceId)
	if resource == "instance/" {
		resource = "instance/" + arnTail(aws.ToString(ci.ContainerInstanceArn))
	}

	agentVersion := ""
	if ci.VersionInfo != nil {
		agentVersion = aws.ToString(ci.VersionInfo.AgentVersion)
	}
	windows := containerInstanceAttribute(ci, "ecs.os-type") == "windows"
	minRequired := [3]int{1, 50, 2}
	if windows {
		minRequired = [3]int{1, 56, 0}
	}

	version, ok := parseVersion(agentVersion)
	if !ok {
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelUnknown,
			Resource: resource,
			Message:  fmt.Sprintf("could not parse ECS agent version %q", agentVersion),
		}}
	}
	if !versionAtLeast(version, minRequired) {
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelError,
			Resource: resource,
			Message: fmt.Sprintf("ECS container agent %s does not support ECS Exec (requires %s)",
				agentVersion, formatVersion(minRequired)),
			Remediation: "Update the ECS container agent (or replace the instance with a recent ECS-optimized AMI). " +
				"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-agent-update.html",
		}}
	}
	return []Finding{{
		CheckID:  c.ID(),
		Level:    LevelOK,
		Resource: resource,
		Message:  fmt.Sprintf("ECS container agent %s supports ECS Exec (>= %s)", agentVersion, formatVersion(minRequired)),
	}}
}

func containerInstanceAttribute(ci *ecstypes.ContainerInstance, name string) string {
	for _, attr := range ci.Attributes {
		if aws.ToString(attr.Name) == name {
			return aws.ToString(attr.Value)
		}
	}
	return ""
}
