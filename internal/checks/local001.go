package checks

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/toricls/verify-exec/internal/collect"
)

// LOCAL-001: Session Manager Plugin is installed. Unconditional must:
// the product assumes users run ECS Exec via the AWS CLI + Session
// Manager Plugin, so there is no flag to opt out of this check.
type local001 struct {
	lookPath   func(file string) (string, error)
	runVersion func(path string) (string, error)
}

func NewLocal001() Check {
	return &local001{
		lookPath: exec.LookPath,
		runVersion: func(path string) (string, error) {
			out, err := exec.Command(path, "--version").CombinedOutput()
			return strings.TrimSpace(string(out)), err
		},
	}
}

func (c *local001) ID() string                          { return "LOCAL-001" }
func (c *local001) Name() string                        { return "Session Manager Plugin installed" }
func (c *local001) DependsOn() []collect.Field          { return nil }
func (c *local001) Applicable(s *collect.Snapshot) bool { return true }

func (c *local001) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	const remediation = "Install the Session Manager Plugin: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html"

	path, err := c.lookPath("session-manager-plugin")
	if err != nil {
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    "local",
			Message:     "session-manager-plugin not found in PATH",
			Remediation: remediation,
		}}
	}
	version, err := c.runVersion(path)
	if err != nil {
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    "local",
			Message:     fmt.Sprintf("session-manager-plugin found at %s but 'session-manager-plugin --version' failed: %v", path, err),
			Remediation: remediation,
		}}
	}
	return []Finding{{
		CheckID:  c.ID(),
		Level:    LevelOK,
		Resource: "local",
		Message:  fmt.Sprintf("session-manager-plugin %s found at %s", version, path),
	}}
}
