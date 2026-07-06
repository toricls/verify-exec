# verify-exec

## Checks

### LOCAL — Local execution environment

This tool assumes the user's execution environment is "AWS CLI + Session Manager Plugin". Both are **must conditions (always error)**.

| ID | Check | Level on failure | Depends on | Applicability |
|---|---|---|---|---|
| LOCAL-001 | Session Manager Plugin is installed (locate `session-manager-plugin` on PATH and run `--version`) | error | None | Always |
| LOCAL-002 | AWS CLI is installed and its version is v1.22.3+ / v2.3.6+ (parse `aws --version`) | error | None | Always |

### CLUSTER — Cluster configuration

| ID | Check | Level on failure | Depends on | Applicability |
|---|---|---|---|---|
| CLUSTER-001 | The cluster exists and is `ACTIVE` | error | Cluster | Always |
| CLUSTER-002 | Audit logging via `executeCommandConfiguration` is configured (`logging != NONE`) | warn | Cluster | Always |
| CLUSTER-003 | The specified KMS key exists and is `Enabled` | error | ExecLogConfig | Only when `kmsKeyId` is set |
| CLUSTER-004 | The CloudWatch Logs group exists. When `cloudWatchEncryptionEnabled=true`, the log group is KMS-encrypted | error | ExecLogConfig | Only when `logging=OVERRIDE` with CW configured |
| CLUSTER-005 | The S3 bucket exists. When `s3EncryptionEnabled=true`, bucket encryption is configured | error | ExecLogConfig | Only when `logging=OVERRIDE` with S3 configured |

### TASK — Task runtime state

| ID | Check | Level on failure | Depends on | Applicability |
|---|---|---|---|---|
| TASK-001 | The task is `RUNNING`. `PROVISIONING`/`PENDING`/`ACTIVATING` are warn (still starting); `DEACTIVATING` and later, and `STOPPED`, are error | error / warn | Task | Always |
| TASK-002 | `enableExecuteCommand = true` | error | Task | Always |
| TASK-003 | The ManagedAgent `ExecuteCommandAgent` is `RUNNING` in each container (**emit container-granularity findings**; include the `reason` in the message when stopped) | error | Task | Always |
| TASK-004 | Fargate Platform Version is Linux `>= 1.4.0` / Windows `>= 1.0.0` | error | Task | launchType=FARGATE |
| TASK-005 | ECS Container Agent version `>= 1.50.2` (`>= 1.56` for Windows AMIs) | error | ContainerInstance | launchType=EC2 / EXTERNAL |

**Fail-fast chain**: when TASK-001 resolves as error (STOPPED family), cancel the `TaskRole` / `Network` / `ContainerInstance` promises and immediately settle all dependent checks as `skip`.

### TDEF — Task definition

| ID | Check | Level on failure | Depends on | Applicability |
|---|---|---|---|---|
| TDEF-001 | `readonlyRootFilesystem` is not `true` on any container (container granularity) | error | TaskDefinition | Always |
| TDEF-002 | `linuxParameters.initProcessEnabled = true` on each container (zombie-process mitigation) | warn | TaskDefinition | Linux containers only |
| TDEF-003 | `pidMode` is not `task` (with PID sharing, only one container can be exec'd into) | warn | TaskDefinition | Always |
| TDEF-004 | No container defines `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_ACCESS_KEY` as environment variables (they can pollute the SSM Agent's credential chain) | warn | TaskDefinition | Always |
| TDEF-005 | A Task Role is set. With the EC2 launch type, the task falls back to the instance role when unset, so error only when both are missing | error | TaskDefinition, ContainerInstance | Always |
| TDEF-006 | When `HTTP_PROXY`/`HTTPS_PROXY` are defined, `NO_PROXY` includes `169.254.169.254,169.254.170.2` | warn | TaskDefinition | Only when proxy environment variables are defined |

### IAM — Permissions

All checks are based on `iam:SimulatePrincipalPolicy`.

TODO: describe about the IAM simulation limitations (Conditions, etc.) and how they are handled.

| ID | Check | Level on failure | Depends on | Applicability |
|---|---|---|---|---|
| IAM-001 | The Task Role (or the EC2 instance role) has the SSM channel permissions: `ssmmessages:CreateControlChannel` / `CreateDataChannel` / `OpenControlChannel` / `OpenDataChannel` | error | TaskRole | Always |
| IAM-002 | The caller (CallerIdentity) is allowed `ecs:ExecuteCommand` on the target task/cluster ARNs | error | CallerIdentity, Task | Always |
| IAM-003 | The caller is allowed `kms:GenerateDataKey` | error | CallerIdentity, ExecLogConfig | Only when KMS is configured |
| IAM-004 | The Task Role is allowed `kms:Decrypt` | error | TaskRole, ExecLogConfig | Only when KMS is configured |
| IAM-005 | The Task Role has CloudWatch Logs write permissions (`logs:CreateLogStream` / `DescribeLogStreams` / `DescribeLogGroups` / `PutLogEvents`) | warn | TaskRole, ExecLogConfig | Only when CW logging is configured |
| IAM-006 | The Task Role has S3 write permissions (`s3:PutObject` / `GetBucketLocation`, plus `GetEncryptionConfiguration` when encryption is on) | warn | TaskRole, ExecLogConfig | Only when S3 logging is configured |
| IAM-007 | The caller's `ssm:StartSession` is **denied** (if it is allowed, an unlogged session bypassing ECS Exec is possible, so emit warn. Note the polarity of this check is inverted relative to the others) | warn | CallerIdentity, Task | Always |

### NET — Networking

| ID | Check | Level on failure | Depends on | Applicability |
|---|---|---|---|---|
| NET-001 | The task ENI is not an IPv6-only configuration (unsupported by ECS Exec) | error | Network | awsvpc mode only |
| NET-002 | Outbound path determination: the subnet's route table has an IGW / NAT GW route; if not, a `com.amazonaws.<region>.ssmmessages` VPC endpoint exists. Decision table: route exists → ok / no route, endpoint exists → ok / no route, no endpoint → **error** / route unknown (other VPC endpoints exist) → **warn** / cannot query due to RAM-shared subnets etc. → **unknown** | error / warn / unknown | Network | awsvpc mode only |
| NET-003 | When KMS is used and the subnet is private, a `com.amazonaws.<region>.kms` endpoint exists | warn | Network, ExecLogConfig | Only when KMS is configured and NET-002 determined there is no route |
