package checks

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/toricls/verify-exec/internal/collect"
)

// TASK-003: the ExecuteCommandAgent managed agent is RUNNING in every
// container (one finding per container, since agent state differs per
// container). When the task itself
// is not RUNNING the agent state is meaningless, so the check is
// reported as skip.
type task003 struct{}

func NewTask003() Check { return &task003{} }

func (c *task003) ID() string                          { return "TASK-003" }
func (c *task003) Name() string                        { return "ExecuteCommandAgent running" }
func (c *task003) DependsOn() []collect.Field          { return []collect.Field{collect.FieldTask} }
func (c *task003) Applicable(s *collect.Snapshot) bool { return true }

func (c *task003) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	task, err := s.Task.Get(ctx)
	if err != nil {
		return nil
	}

	if collect.ClassifyTaskStatus(aws.ToString(task.LastStatus)) != collect.TaskRunning {
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelSkip,
			Resource: taskResource(task),
			Message:  fmt.Sprintf("task is %s; agent status not evaluated", aws.ToString(task.LastStatus)),
		}}
	}

	var findings []Finding
	for _, container := range task.Containers {
		name := aws.ToString(container.Name)
		agent, found := execCommandAgent(container)

		switch {
		case !found:
			findings = append(findings, Finding{
				CheckID:  c.ID(),
				Level:    LevelError,
				Resource: containerResource(name),
				Message:  "ExecuteCommandAgent is not present on this container",
				Remediation: "The agent is injected only when the task starts with execute command enabled. " +
					"Re-run the task with --enable-execute-command. " + docTroubleshooting,
			})
		case aws.ToString(agent.LastStatus) != "RUNNING":
			msg := fmt.Sprintf("ExecuteCommandAgent is %s", aws.ToString(agent.LastStatus))
			if reason := aws.ToString(agent.Reason); reason != "" {
				msg += fmt.Sprintf(" (reason: %s)", reason)
			}
			findings = append(findings, Finding{
				CheckID:     c.ID(),
				Level:       LevelError,
				Resource:    containerResource(name),
				Message:     msg,
				Remediation: "See the ECS Exec troubleshooting guide: " + docTroubleshooting,
			})
		default:
			findings = append(findings, Finding{
				CheckID:  c.ID(),
				Level:    LevelOK,
				Resource: containerResource(name),
				Message:  "ExecuteCommandAgent is RUNNING",
			})
		}
	}
	return findings
}

func execCommandAgent(container ecstypes.Container) (ecstypes.ManagedAgent, bool) {
	for _, agent := range container.ManagedAgents {
		if agent.Name == ecstypes.ManagedAgentNameExecuteCommandAgent {
			return agent, true
		}
	}
	return ecstypes.ManagedAgent{}, false
}
