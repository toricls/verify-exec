package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/toricls/verify-exec/internal/collect"
)

// TDEF-006: containers routing traffic through an HTTP(S) proxy must
// exclude the metadata endpoints via NO_PROXY, or the SSM agent cannot
// reach its credentials.
type tdef006 struct{}

func NewTdef006() Check { return &tdef006{} }

func (c *tdef006) ID() string   { return "TDEF-006" }
func (c *tdef006) Name() string { return "Proxy excludes metadata endpoints" }
func (c *tdef006) DependsOn() []collect.Field {
	return []collect.Field{collect.FieldTaskDefinition}
}

func (c *tdef006) Applicable(s *collect.Snapshot) bool {
	for _, cd := range resolved(s.TaskDefinition).ContainerDefinitions {
		if hasProxyEnv(cd) {
			return true
		}
	}
	return false
}

// noProxyRequired are the endpoints the SSM agent must reach directly:
// the EC2 instance metadata service and the ECS task metadata /
// credentials endpoint.
var noProxyRequired = []string{"169.254.169.254", "169.254.170.2"}

func (c *tdef006) Run(ctx context.Context, s *collect.Snapshot) []Finding {
	taskDef := resolved(s.TaskDefinition)

	var findings []Finding
	for _, cd := range taskDef.ContainerDefinitions {
		if !hasProxyEnv(cd) {
			continue
		}
		name := aws.ToString(cd.Name)
		noProxy := envValue(cd, "NO_PROXY") + "," + envValue(cd, "no_proxy")

		var missing []string
		for _, endpoint := range noProxyRequired {
			if !strings.Contains(noProxy, endpoint) {
				missing = append(missing, endpoint)
			}
		}
		if len(missing) > 0 {
			findings = append(findings, Finding{
				CheckID:  c.ID(),
				Level:    LevelWarn,
				Resource: containerResource(name),
				Message:  fmt.Sprintf("HTTP proxy is configured but NO_PROXY does not include %s; the SSM agent may fail to fetch credentials", strings.Join(missing, ", ")),
				Remediation: "Add 169.254.169.254,169.254.170.2 to the NO_PROXY environment variable. " +
					docTroubleshooting,
			})
		} else {
			findings = append(findings, Finding{
				CheckID:  c.ID(),
				Level:    LevelOK,
				Resource: containerResource(name),
				Message:  "NO_PROXY covers the metadata endpoints",
			})
		}
	}
	return findings
}

func hasProxyEnv(cd ecstypes.ContainerDefinition) bool {
	for _, proxy := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if envValue(cd, proxy) != "" {
			return true
		}
	}
	return false
}

func envValue(cd ecstypes.ContainerDefinition, name string) string {
	for _, env := range cd.Environment {
		if aws.ToString(env.Name) == name {
			return aws.ToString(env.Value)
		}
	}
	return ""
}
