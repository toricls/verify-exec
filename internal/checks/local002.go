package checks

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/toricls/verify-exec/internal/collect"
)

// LOCAL-002: AWS CLI is installed at v1.22.3+ / v2.3.6+. Unconditional
// must, same as LOCAL-001: the AWS CLI is the assumed ECS Exec client.
type local002 struct {
	awsVersion func() (string, error)
}

func NewLocal002() Check {
	return &local002{
		awsVersion: func() (string, error) {
			// AWS CLI v1 may print the version banner to stderr.
			out, err := exec.Command("aws", "--version").CombinedOutput()
			return strings.TrimSpace(string(out)), err
		},
	}
}

func (c *local002) ID() string                          { return "LOCAL-002" }
func (c *local002) Name() string                        { return "AWS CLI version" }
func (c *local002) DependsOn() []collect.Field          { return nil }
func (c *local002) Applicable(s *collect.Snapshot) bool { return true }

var (
	awsCLIVersionRe = regexp.MustCompile(`aws-cli/(\d+)\.(\d+)\.(\d+)`)

	minCLIv1 = [3]int{1, 22, 3}
	minCLIv2 = [3]int{2, 3, 6}
)

func (c *local002) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	const remediation = "Install or upgrade the AWS CLI (v1.22.3+ / v2.3.6+): https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"

	out, err := c.awsVersion()
	if err != nil && out == "" {
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    "local",
			Message:     fmt.Sprintf("AWS CLI not found or 'aws --version' failed: %v", err),
			Remediation: remediation,
		}}
	}

	version, ok := parseAWSCLIVersion(out)
	if !ok {
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelUnknown,
			Resource:    "local",
			Message:     fmt.Sprintf("could not parse AWS CLI version from %q", out),
			Remediation: remediation,
		}}
	}

	var minRequired [3]int
	switch version[0] {
	case 1:
		minRequired = minCLIv1
	case 2:
		minRequired = minCLIv2
	default:
		// Future major versions are assumed to satisfy the requirement.
		return []Finding{{
			CheckID:  c.ID(),
			Level:    LevelOK,
			Resource: "local",
			Message:  fmt.Sprintf("AWS CLI %s found", formatVersion(version)),
		}}
	}

	if !versionAtLeast(version, minRequired) {
		return []Finding{{
			CheckID:     c.ID(),
			Level:       LevelError,
			Resource:    "local",
			Message:     fmt.Sprintf("AWS CLI %s is older than required %s for ECS Exec", formatVersion(version), formatVersion(minRequired)),
			Remediation: remediation,
		}}
	}
	return []Finding{{
		CheckID:  c.ID(),
		Level:    LevelOK,
		Resource: "local",
		Message:  fmt.Sprintf("AWS CLI %s found (>= %s)", formatVersion(version), formatVersion(minRequired)),
	}}
}

func parseAWSCLIVersion(out string) ([3]int, bool) {
	m := awsCLIVersionRe.FindStringSubmatch(out)
	if m == nil {
		return [3]int{}, false
	}
	var v [3]int
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return [3]int{}, false
		}
		v[i] = n
	}
	return v, true
}

func versionAtLeast(v, min [3]int) bool {
	for i := 0; i < 3; i++ {
		if v[i] != min[i] {
			return v[i] > min[i]
		}
	}
	return true
}

func formatVersion(v [3]int) string {
	return fmt.Sprintf("v%d.%d.%d", v[0], v[1], v[2])
}
