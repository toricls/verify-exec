package checks

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/toricls/verify-exec/internal/collect"
)

// resolved returns a promise's value, discarding errors. Only valid in
// Applicable/Run, where the runner has already waited on the declared
// dependencies (an errored dependency never reaches these methods).
func resolved[T any](p *collect.Promise[T]) T {
	v, _ := p.Get(context.Background())
	return v
}

func taskDefResource(td *ecstypes.TaskDefinition) string {
	return fmt.Sprintf("taskdefinition/%s:%d", aws.ToString(td.Family), td.Revision)
}

// arnTail returns the substring after the final "/" of an ARN.
func arnTail(arn string) string {
	if i := strings.LastIndexByte(arn, '/'); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

func isFargate(task *ecstypes.Task) bool {
	return task.LaunchType == ecstypes.LaunchTypeFargate
}

func isEC2OrExternal(task *ecstypes.Task) bool {
	return task.LaunchType == ecstypes.LaunchTypeEc2 || task.LaunchType == ecstypes.LaunchTypeExternal
}

// isWindowsTaskDef reports whether the task definition targets a
// Windows OS family. A nil runtimePlatform means Linux.
func isWindowsTaskDef(td *ecstypes.TaskDefinition) bool {
	return td.RuntimePlatform != nil &&
		strings.HasPrefix(string(td.RuntimePlatform.OperatingSystemFamily), "WINDOWS")
}

// parseVersion parses a dotted version like "1.4.0" or "1.56" into a
// comparable [3]int (missing parts are zero). Suffixes after "-" are
// ignored ("1.51.0-1" → 1.51.0).
func parseVersion(s string) ([3]int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return [3]int{}, false
	}
	var v [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return [3]int{}, false
		}
		v[i] = n
	}
	return v, true
}

// simFinding maps a SimulatePrincipalPolicy outcome to a finding
// following the settled IAM verdict rules: allowed → ok; denied with
// no Condition involvement → failLevel; denied but condition-dependent
// → unknown (prompt an actual attempt); simulation failed → unknown.
func simFinding(checkID, resource, principal string, outcome *collect.SimOutcome, failLevel Level, subject, remediation string) Finding {
	f := Finding{CheckID: checkID, Resource: resource}
	switch {
	case outcome == nil:
		f.Level = LevelUnknown
		f.Message = fmt.Sprintf("%s: no simulation result", subject)
	case outcome.Err != nil:
		f.Level = LevelUnknown
		f.Message = fmt.Sprintf("could not evaluate %s: %v", subject, outcome.Err)
	case len(outcome.DeniedActions) > 0:
		f.Level = failLevel
		f.Message = fmt.Sprintf("%s is denied %s: %s", principal, subject, strings.Join(outcome.DeniedActions, ", "))
		f.Remediation = remediation
	case outcome.ConditionDependent():
		f.Level = LevelUnknown
		f.Message = fmt.Sprintf("%s for %s depends on policy Conditions (missing context: %s); cannot be determined statically — verify by running 'aws ecs execute-command'",
			subject, principal, strings.Join(outcome.MissingContext, ", "))
	default:
		f.Level = LevelOK
		f.Message = fmt.Sprintf("%s is allowed %s", principal, subject)
		if outcome.Note != "" {
			f.Message += " (" + outcome.Note + ")"
		}
	}
	return f
}
