package collect

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var ssmChannelActions = []string{
	"ssmmessages:CreateControlChannel",
	"ssmmessages:CreateDataChannel",
	"ssmmessages:OpenControlChannel",
	"ssmmessages:OpenDataChannel",
}

var cwLogsActions = []string{
	"logs:CreateLogStream",
	"logs:DescribeLogStreams",
	"logs:DescribeLogGroups",
	"logs:PutLogEvents",
}

func collectTaskRole(ctx context.Context, deps Deps, s *Snapshot) {
	task, err := s.gate(ctx)
	if err != nil {
		s.TaskRole.Complete(nil, err)
		return
	}
	taskDef, err := s.TaskDefinition.Get(ctx)
	if err != nil {
		s.TaskRole.Complete(nil, fmt.Errorf("task role unavailable: %w", err))
		return
	}

	info := &IAMRoleInfo{Source: RoleSourceNone}
	roleArn := ""
	if task.Overrides != nil {
		roleArn = aws.ToString(task.Overrides.TaskRoleArn)
	}
	if roleArn == "" {
		roleArn = aws.ToString(taskDef.TaskRoleArn)
	}
	if roleArn != "" {
		info.Source = RoleSourceTaskRole
	} else if task.LaunchType == ecstypes.LaunchTypeEc2 || task.LaunchType == ecstypes.LaunchTypeExternal {
		// Without a task role, credentials come from the container
		// instance's role, so evaluate that instead.
		roleArn, err = resolveInstanceRole(ctx, deps, s)
		switch {
		case err != nil:
			info.ResolveErr = err
		case roleArn != "":
			info.Source = RoleSourceInstanceRole
		}
	}
	if roleArn != "" {
		info.Arn = roleArn
		info.Name = arnLastSegment(roleArn)
		runRoleSimulations(ctx, deps, s, info, aws.ToString(task.TaskArn))
	}
	s.TaskRole.Complete(info, nil)
}

// resolveInstanceRole follows container instance → EC2 instance →
// instance profile → role. Returns "" (no error) when the instance
// simply has no instance profile.
func resolveInstanceRole(ctx context.Context, deps Deps, s *Snapshot) (string, error) {
	ci, err := s.ContainerInstance.Get(ctx)
	if err != nil || ci == nil {
		return "", fmt.Errorf("container instance unavailable: %w", err)
	}
	instanceID := aws.ToString(ci.Ec2InstanceId)
	if instanceID == "" {
		return "", nil
	}
	out, err := deps.EC2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return "", fmt.Errorf("DescribeInstances failed: %w", err)
	}
	if len(out.Reservations) == 0 || len(out.Reservations[0].Instances) == 0 {
		return "", fmt.Errorf("EC2 instance %q not found", instanceID)
	}
	profile := out.Reservations[0].Instances[0].IamInstanceProfile
	if profile == nil {
		return "", nil
	}
	profileName := arnLastSegment(aws.ToString(profile.Arn))
	pout, err := deps.IAM.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
	})
	if err != nil {
		return "", fmt.Errorf("GetInstanceProfile failed: %w", err)
	}
	if len(pout.InstanceProfile.Roles) == 0 {
		return "", nil
	}
	return aws.ToString(pout.InstanceProfile.Roles[0].Arn), nil
}

// runRoleSimulations fills in the role-side simulation outcomes.
// taskArn provides the region/account for constructing resource ARNs
// (the role ARN itself has an empty region field).
func runRoleSimulations(ctx context.Context, deps Deps, s *Snapshot, info *IAMRoleInfo, taskArn string) {
	info.SSMChannel = simulate(ctx, deps, info.Arn, ssmChannelActions, nil)

	// The log-destination simulations need the resolved cluster config.
	logCfg, err := s.ExecLogConfig.Get(ctx)
	if err != nil {
		outcome := &SimOutcome{Err: fmt.Errorf("exec log config unavailable: %w", err)}
		info.KMSDecrypt, info.CWLogs, info.S3Write = outcome, outcome, outcome
		return
	}
	if keyArn := logCfg.KMSKeyArn(); keyArn != "" {
		info.KMSDecrypt = simulate(ctx, deps, info.Arn, []string{"kms:Decrypt"}, []string{keyArn})
	}
	if cw := logCfg.CloudWatch; cw != nil {
		var resources []string
		if region, account, ok := arnRegionAccount(taskArn); ok {
			resources = []string{fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s:*", region, account, cw.GroupName)}
		}
		info.CWLogs = simulate(ctx, deps, info.Arn, cwLogsActions, resources)
	}
	if s3Dest := logCfg.S3; s3Dest != nil {
		putOutcome := simulate(ctx, deps, info.Arn,
			[]string{"s3:PutObject"},
			[]string{fmt.Sprintf("arn:aws:s3:::%s/*", s3Dest.Bucket)})
		bucketActions := []string{"s3:GetBucketLocation"}
		if s3Dest.EncryptionEnabled {
			bucketActions = append(bucketActions, "s3:GetEncryptionConfiguration")
		}
		bucketOutcome := simulate(ctx, deps, info.Arn, bucketActions,
			[]string{fmt.Sprintf("arn:aws:s3:::%s", s3Dest.Bucket)})
		info.S3Write = mergeOutcomes(putOutcome, bucketOutcome)
	}
}

func collectCallerIdentity(ctx context.Context, deps Deps, s *Snapshot) {
	out, err := deps.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		s.CallerIdentity.Complete(nil, fmt.Errorf("GetCallerIdentity failed: %w", err))
		return
	}
	info := &CallerInfo{
		Arn:     aws.ToString(out.Arn),
		Account: aws.ToString(out.Account),
	}
	principal, note, kind := simulatablePrincipal(info.Arn)
	info.SimPrincipal = principal
	info.SimPrincipalNote = note

	// The caller-side simulations run even for a stopped task
	// (deliberately not gated on the fail-fast): they only need ARNs.
	task, taskErr := s.Task.Get(ctx)
	logCfg, logErr := s.ExecLogConfig.Get(ctx)

	sim := func(actions, resources []string) *SimOutcome {
		switch kind {
		case principalRoot:
			// The root user bypasses IAM policy evaluation entirely.
			return &SimOutcome{Note: "root credentials: IAM policies do not restrict the root user"}
		case principalUnsimulatable:
			return &SimOutcome{Err: fmt.Errorf("principal %q cannot be simulated: %s", info.Arn, note)}
		}
		return simulate(ctx, deps, principal, actions, resources)
	}

	if taskErr != nil {
		outcome := &SimOutcome{Err: fmt.Errorf("task unavailable: %w", taskErr)}
		info.ExecuteCommand, info.SSMStartSession = outcome, outcome
	} else {
		taskArn := aws.ToString(task.TaskArn)
		clusterArn := aws.ToString(task.ClusterArn)
		info.ExecuteCommand = sim([]string{"ecs:ExecuteCommand"}, []string{clusterArn, taskArn})
		info.SSMStartSession = sim([]string{"ssm:StartSession"}, []string{taskArn})
	}
	switch {
	case logErr != nil:
		info.KMSGenerateDataKey = &SimOutcome{Err: fmt.Errorf("exec log config unavailable: %w", logErr)}
	case logCfg.KMSKeyArn() != "":
		info.KMSGenerateDataKey = sim([]string{"kms:GenerateDataKey"}, []string{logCfg.KMSKeyArn()})
	}
	s.CallerIdentity.Complete(info, nil)
}

// simulate runs one SimulatePrincipalPolicy call and digests the
// per-action (and per-resource) decisions into a SimOutcome. Denies
// that reported missing context values are recorded as
// condition-dependent: a Condition might allow them at runtime, so no
// definitive verdict is possible (they map to unknown, not failure).
func simulate(ctx context.Context, deps Deps, principalArn string, actions, resources []string) *SimOutcome {
	in := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(principalArn),
		ActionNames:     actions,
	}
	if len(resources) > 0 {
		in.ResourceArns = resources
	}
	out, err := deps.IAM.SimulatePrincipalPolicy(ctx, in)
	if err != nil {
		return &SimOutcome{Err: fmt.Errorf("SimulatePrincipalPolicy failed: %w", err)}
	}
	outcome := &SimOutcome{}
	for _, result := range out.EvaluationResults {
		action := aws.ToString(result.EvalActionName)
		if len(result.ResourceSpecificResults) > 0 {
			for _, rr := range result.ResourceSpecificResults {
				recordDecision(outcome, action, string(rr.EvalResourceDecision), rr.MissingContextValues)
			}
		} else {
			recordDecision(outcome, action, string(result.EvalDecision), result.MissingContextValues)
		}
	}
	return outcome
}

func recordDecision(o *SimOutcome, action, decision string, missingContext []string) {
	if decision == string(iamtypes.PolicyEvaluationDecisionTypeAllowed) {
		return
	}
	if len(missingContext) > 0 {
		o.ConditionActions = appendUnique(o.ConditionActions, action)
		for _, key := range missingContext {
			o.MissingContext = appendUnique(o.MissingContext, key)
		}
		return
	}
	o.DeniedActions = appendUnique(o.DeniedActions, action)
}

func mergeOutcomes(a, b *SimOutcome) *SimOutcome {
	merged := &SimOutcome{}
	for _, o := range []*SimOutcome{a, b} {
		if o == nil {
			continue
		}
		if o.Err != nil && merged.Err == nil {
			merged.Err = o.Err
		}
		for _, x := range o.DeniedActions {
			merged.DeniedActions = appendUnique(merged.DeniedActions, x)
		}
		for _, x := range o.ConditionActions {
			merged.ConditionActions = appendUnique(merged.ConditionActions, x)
		}
		for _, x := range o.MissingContext {
			merged.MissingContext = appendUnique(merged.MissingContext, x)
		}
	}
	return merged
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

type principalKind int

const (
	principalSimulatable principalKind = iota
	principalRoot
	principalUnsimulatable
)

// simulatablePrincipal converts a GetCallerIdentity ARN into an ARN
// usable as SimulatePrincipalPolicy's PolicySourceArn. STS
// assumed-role ARNs are rewritten to the underlying IAM role ARN.
func simulatablePrincipal(callerArn string) (arn string, note string, kind principalKind) {
	parts := strings.SplitN(callerArn, ":", 6)
	if len(parts) != 6 {
		return "", "unrecognized ARN format", principalUnsimulatable
	}
	service, account, resource := parts[2], parts[4], parts[5]
	switch {
	case resource == "root":
		return "", "root user", principalRoot
	case service == "iam" && (strings.HasPrefix(resource, "user/") || strings.HasPrefix(resource, "role/")):
		return callerArn, "", principalSimulatable
	case service == "sts" && strings.HasPrefix(resource, "assumed-role/"):
		seg := strings.Split(resource, "/")
		if len(seg) < 2 {
			return "", "unrecognized assumed-role ARN", principalUnsimulatable
		}
		roleArn := fmt.Sprintf("arn:%s:iam::%s:role/%s", parts[1], account, seg[1])
		return roleArn, fmt.Sprintf("evaluated as role %s", seg[1]), principalSimulatable
	case service == "sts" && strings.HasPrefix(resource, "federated-user/"):
		return "", "federated user (no IAM entity to simulate)", principalUnsimulatable
	default:
		return "", fmt.Sprintf("unsupported principal type %q", resource), principalUnsimulatable
	}
}

// arnLastSegment returns the substring after the final "/" (or ":").
func arnLastSegment(arn string) string {
	if i := strings.LastIndexAny(arn, "/:"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

// arnRegionAccount extracts the region and account fields of an ARN.
// Region may legitimately be empty (e.g. IAM ARNs).
func arnRegionAccount(arn string) (region, account string, ok bool) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 {
		return "", "", false
	}
	return parts[3], parts[4], true
}
