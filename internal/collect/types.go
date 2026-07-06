package collect

import (
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Collected-value types. Convention: a promise only fails (resolves
// with an error) when its upstream promise failed or the fail-fast
// cancellation fired. Leaf lookups that can be blocked by missing
// permissions (kms:DescribeKey, iam:Simulate*, ec2:Describe*, …) embed
// their error in these structs instead, so the affected checks report
// unknown without turning the whole run into a tool failure.

// ClusterInfo carries the requested cluster name alongside the API
// result. Cluster == nil (with no promise error) means the cluster was
// confirmed absent, which CLUSTER-001 reports as error.
type ClusterInfo struct {
	Name    string
	Cluster *ecstypes.Cluster
}

// LogConfigInfo is the resolved executeCommandConfiguration of the
// cluster: the raw settings plus the existence/state lookups of the
// referenced KMS key, CloudWatch Logs group, and S3 bucket.
type LogConfigInfo struct {
	ClusterName string
	// Logging is empty when the cluster has no executeCommandConfiguration.
	Logging ecstypes.ExecuteCommandLogging

	KMSKeyID      string // as configured; empty = no KMS encryption
	KMSKey        *kmstypes.KeyMetadata
	KMSKeyMissing bool  // DescribeKey said the key does not exist
	KMSKeyErr     error // DescribeKey failed for another reason

	CloudWatch *CloudWatchLogDest // nil unless logging=OVERRIDE with a CW group
	S3         *S3LogDest         // nil unless logging=OVERRIDE with an S3 bucket
}

// KMSKeyArn returns the best-known ARN (or ID) usable as a simulation
// resource, empty when KMS is not configured.
func (l *LogConfigInfo) KMSKeyArn() string {
	if l.KMSKey != nil {
		if arn := l.KMSKey.Arn; arn != nil && *arn != "" {
			return *arn
		}
	}
	return l.KMSKeyID
}

type CloudWatchLogDest struct {
	GroupName         string
	EncryptionEnabled bool                // cloudWatchEncryptionEnabled
	Group             *logstypes.LogGroup // nil = group not found (when Err is nil)
	Err               error
}

type S3LogDest struct {
	Bucket            string
	KeyPrefix         string
	EncryptionEnabled bool // s3EncryptionEnabled
	Exists            bool
	Err               error // HeadBucket failed in a way that leaves existence unknown
	Encrypted         bool
	EncryptionErr     error // GetBucketEncryption failed
}

// RoleSource says where the task's effective IAM role came from.
type RoleSource string

const (
	RoleSourceTaskRole     RoleSource = "taskRole"
	RoleSourceInstanceRole RoleSource = "instanceRole"
	RoleSourceNone         RoleSource = "none"
)

// IAMRoleInfo is the task's effective role (task role, or the EC2
// instance role as fallback) plus the policy-simulation outcomes for
// the role-side IAM checks.
type IAMRoleInfo struct {
	Arn        string
	Name       string
	Source     RoleSource
	ResolveErr error // the instance-role fallback lookup failed

	SSMChannel *SimOutcome // ssmmessages:* channel actions (IAM-001)
	KMSDecrypt *SimOutcome // nil unless KMS is configured (IAM-004)
	CWLogs     *SimOutcome // nil unless CW logging is configured (IAM-005)
	S3Write    *SimOutcome // nil unless S3 logging is configured (IAM-006)
}

// CallerInfo is the caller identity plus the policy-simulation
// outcomes for the caller-side IAM checks.
type CallerInfo struct {
	Arn     string
	Account string
	// SimPrincipal is the IAM principal ARN used for simulation
	// (assumed-role ARNs are rewritten to the underlying role ARN).
	// Empty when the principal cannot be simulated (root, federated).
	SimPrincipal     string
	SimPrincipalNote string

	ExecuteCommand     *SimOutcome // ecs:ExecuteCommand (IAM-002)
	KMSGenerateDataKey *SimOutcome // nil unless KMS is configured (IAM-003)
	SSMStartSession    *SimOutcome // ssm:StartSession (IAM-007, inverted polarity)
}

// SimOutcome is the digested result of one SimulatePrincipalPolicy
// evaluation (possibly merged across calls).
type SimOutcome struct {
	Err error // the simulation itself failed (e.g. no iam:SimulatePrincipalPolicy)
	// DeniedActions were denied by statements that did not depend on
	// missing context values: a definitive deny.
	DeniedActions []string
	// ConditionActions were denied, but context values were missing
	// during simulation, so a Condition may allow them at runtime.
	// Definitive verdicts are impossible for these.
	ConditionActions []string
	MissingContext   []string
	Note             string
}

// Allowed reports a definitive full allow.
func (o *SimOutcome) Allowed() bool {
	return o.Err == nil && len(o.DeniedActions) == 0 && len(o.ConditionActions) == 0
}

// ConditionDependent reports "no definitive deny, but at least one
// action hinges on a Condition we could not evaluate".
func (o *SimOutcome) ConditionDependent() bool {
	return o.Err == nil && len(o.DeniedActions) == 0 && len(o.ConditionActions) > 0
}

// NetworkInfo is the resolved network path of the task ENI:
// subnet → route table → VPC endpoints.
type NetworkInfo struct {
	Awsvpc   bool // task has an ENI attachment (awsvpc network mode)
	ENIID    string
	SubnetID string
	VpcID    string

	IPv6Only  bool
	SubnetErr error // DescribeSubnets failed (e.g. RAM-shared subnet)

	// HasPublicRoute: true = default route via IGW/NAT GW; false = no
	// default route; nil = undetermined (query failed, or the default
	// route points at something we cannot follow, e.g. a TGW).
	HasPublicRoute *bool
	RouteNote      string
	RouteErr       error

	VPCEndpoints []string // service names of available VPC endpoints
	EndpointErr  error
}

// HasEndpoint reports whether a VPC endpoint for the given service
// name exists.
func (n *NetworkInfo) HasEndpoint(service string) bool {
	for _, s := range n.VPCEndpoints {
		if s == service {
			return true
		}
	}
	return false
}
