# verify-exec

🚀 Yet another pre-flight checker for [ECS Exec](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html), written in Go.

`verify-exec` diagnoses whether ECS Exec can be used against a specific `(cluster, task)` pair — *before* you run `aws ecs execute-command` and stare at the infamous `TargetNotConnectedException`. It inspects your local environment, the cluster configuration, the task's runtime state, the task definition, IAM permissions, and networking, then reports every finding at once instead of failing one mystery at a time.

Inspired by [amazon-ecs-exec-checker](https://github.com/aws-containers/amazon-ecs-exec-checker), but built with Go as a single static binary with concurrent checks, machine-readable output, and CI-friendly exit codes.

## Features

- **28 checks across 6 categories** — local environment, cluster, task, task definition, IAM, and networking — run concurrently with automatic dependency resolution and fail-fast skipping
- **Live TUI** on interactive terminals; plain append-only output on pipes/CI; `--output json` for automation
- **CI-friendly exit codes** that distinguish "misconfigured for ECS Exec" from "the tool itself failed"
- **Container-granularity findings** where it matters (managed agent state, `readonlyRootFilesystem`, etc.)
- Single static binary, no runtime dependencies beyond your AWS credentials

## Installation

### From source

```console
go install github.com/toricls/verify-exec/cmd/verify-exec@latest
```

Or clone and build:

```console
git clone https://github.com/toricls/verify-exec.git
cd verify-exec
make build   # binary at ./dist/verify-exec
```

### Pre-built binaries

Download binaries for macOS/Linux (amd64/arm64) from the [Releases](https://github.com/toricls/verify-exec/releases) page.

## Usage

```console
verify-exec <cluster> <task-id> [flags]
```

Example:

```console
$ verify-exec my-cluster 0123456789abcdef0123456789abcdef
```

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--container <name>` | (all) | Limit container-level checks to a single container |
| `--profile <name>` | | AWS profile to use |
| `--region <region>` | | AWS region (falls back to your AWS config) |
| `--output <format>` | `table` | Output format: `table` or `json` |
| `--fail-on <level>` | `error` | Exit non-zero on: `error` or `warn` |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All checks passed (or only warnings, with `--fail-on error`) |
| `1` | Warning findings exist and `--fail-on warn` was set |
| `2` | Error findings exist — the task is misconfigured for ECS Exec |
| `3` | Tool failure (auth error, task not found, invalid flags, …) |

Keeping `2` and `3` distinct lets CI tell "ECS Exec won't work" apart from "the checker could not run".

### Use in CI

```console
verify-exec my-cluster "$TASK_ID" --output json --fail-on warn
```

Non-TTY environments automatically get plain, append-only output; use `--output json` if you want to post-process findings.

## Checks

### LOCAL — Local execution environment

This tool assumes the execution environment is "AWS CLI + Session Manager Plugin". Both are **must conditions (always error)**.

| ID | Check | Level on failure | Applicability |
| --- | --- | --- | --- |
| LOCAL-001 | Session Manager Plugin is installed (`session-manager-plugin` on PATH, `--version` runs) | error | Always |
| LOCAL-002 | AWS CLI is installed and is v1.22.3+ / v2.3.6+ | error | Always |

### CLUSTER — Cluster configuration

| ID | Check | Level on failure | Applicability |
| --- | --- | --- | --- |
| CLUSTER-001 | The cluster exists and is `ACTIVE` | error | Always |
| CLUSTER-002 | Audit logging via `executeCommandConfiguration` is configured (`logging != NONE`) | warn | Always |
| CLUSTER-003 | The specified KMS key exists and is `Enabled` | error | Only when `kmsKeyId` is set |
| CLUSTER-004 | The CloudWatch Logs group exists; when `cloudWatchEncryptionEnabled=true`, it is KMS-encrypted | error | Only when `logging=OVERRIDE` with CloudWatch configured |
| CLUSTER-005 | The S3 bucket exists; when `s3EncryptionEnabled=true`, bucket encryption is configured | error | Only when `logging=OVERRIDE` with S3 configured |

### TASK — Task runtime state

| ID | Check | Level on failure | Applicability |
| --- | --- | --- | --- |
| TASK-001 | The task is `RUNNING` (`PROVISIONING`/`PENDING`/`ACTIVATING` → warn; `DEACTIVATING` and later, or `STOPPED` → error) | error / warn | Always |
| TASK-002 | `enableExecuteCommand = true` | error | Always |
| TASK-003 | The `ExecuteCommandAgent` managed agent is `RUNNING` in each container (container-granularity findings; the stop `reason` is included) | error | Always |
| TASK-004 | Fargate platform version is Linux `>= 1.4.0` / Windows `>= 1.0.0` | error | `launchType=FARGATE` |
| TASK-005 | ECS container agent version `>= 1.50.2` (`>= 1.56` for Windows AMIs) | error | `launchType=EC2` / `EXTERNAL` |

When TASK-001 resolves as error (the STOPPED family), dependent checks are cancelled and settled as `skip` (fail-fast).

### TDEF — Task definition

| ID | Check | Level on failure | Applicability |
| --- | --- | --- | --- |
| TDEF-001 | `readonlyRootFilesystem` is not `true` on any container | error | Always |
| TDEF-002 | `linuxParameters.initProcessEnabled = true` on each container (zombie-process mitigation) | warn | Linux containers only |
| TDEF-003 | `pidMode` is not `task` (with PID sharing, only one container can be exec'd into) | warn | Always |
| TDEF-004 | No container defines `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_ACCESS_KEY` as environment variables (they can pollute the SSM Agent's credential chain) | warn | Always |
| TDEF-005 | A task role is set (with the EC2 launch type the task falls back to the instance role, so error only when both are missing) | error | Always |
| TDEF-006 | When `HTTP_PROXY`/`HTTPS_PROXY` are defined, `NO_PROXY` includes `169.254.169.254,169.254.170.2` | warn | Only when proxy env vars are defined |

### IAM — Permissions

All IAM checks are based on `iam:SimulatePrincipalPolicy`. Note that policy simulation has inherent limitations (e.g. condition keys that depend on runtime request context), so results may occasionally differ from actual authorization decisions.

| ID | Check | Level on failure | Applicability |
| --- | --- | --- | --- |
| IAM-001 | The task role (or EC2 instance role) has the SSM channel permissions: `ssmmessages:CreateControlChannel` / `CreateDataChannel` / `OpenControlChannel` / `OpenDataChannel` | error | Always |
| IAM-002 | The caller is allowed `ecs:ExecuteCommand` on the target task/cluster ARNs | error | Always |
| IAM-003 | The caller is allowed `kms:GenerateDataKey` | error | Only when KMS is configured |
| IAM-004 | The task role is allowed `kms:Decrypt` | error | Only when KMS is configured |
| IAM-005 | The task role has CloudWatch Logs write permissions (`logs:CreateLogStream` / `DescribeLogStreams` / `DescribeLogGroups` / `PutLogEvents`) | warn | Only when CloudWatch logging is configured |
| IAM-006 | The task role has S3 write permissions (`s3:PutObject` / `GetBucketLocation`, plus `GetEncryptionConfiguration` when encryption is on) | warn | Only when S3 logging is configured |
| IAM-007 | The caller's `ssm:StartSession` is **denied** — if allowed, an unlogged session bypassing ECS Exec is possible (note: this check's polarity is inverted) | warn | Always |

### NET — Networking

| ID | Check | Level on failure | Applicability |
| --- | --- | --- | --- |
| NET-001 | The task ENI is not IPv6-only (unsupported by ECS Exec) | error | `awsvpc` mode only |
| NET-002 | Outbound path exists: the subnet's route table has an IGW/NAT GW route, or a `com.amazonaws.<region>.ssmmessages` VPC endpoint exists (no route & no endpoint → error; route unknown → warn; unqueryable, e.g. RAM-shared subnets → unknown) | error / warn / unknown | `awsvpc` mode only |
| NET-003 | When KMS is used and the subnet is private, a `com.amazonaws.<region>.kms` endpoint exists | warn | Only when KMS is configured and NET-002 found no route |

## Required permissions for running verify-exec

The IAM principal running `verify-exec` needs read-only access to inspect the resources involved, roughly:

- `ecs:DescribeClusters`, `ecs:DescribeTasks`, `ecs:DescribeTaskDefinition`, `ecs:DescribeContainerInstances`
- `sts:GetCallerIdentity`
- `iam:SimulatePrincipalPolicy`, `iam:GetInstanceProfile`
- `ec2:DescribeNetworkInterfaces`, `ec2:DescribeSubnets`, `ec2:DescribeRouteTables`, `ec2:DescribeVpcEndpoints`
- `kms:DescribeKey`
- `logs:DescribeLogGroups`
- `s3:GetBucketLocation`, `s3:GetEncryptionConfiguration`

No mutating API is ever called.

Use the following policy snippet as a starting point for your read-only role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:DescribeClusters",
        "ecs:DescribeTasks",
        "ecs:DescribeTaskDefinition",
        "ecs:DescribeContainerInstances",
        "sts:GetCallerIdentity",
        "iam:SimulatePrincipalPolicy",
        "iam:GetInstanceProfile",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeVpcEndpoints",
        "kms:DescribeKey",
        "logs:DescribeLogGroups",
        "s3:GetBucketLocation",
        "s3:GetEncryptionConfiguration"
      ],
      "Resource": "*"
    }
  ]
}
```

## Development

```console
make help    # list all targets
make setup   # go mod tidy && download
make test    # go test -race ./...
make ci      # fmt-check + vet + test + build
```

## Contributing

Issues and pull requests are welcome! Please open an issue first for larger changes so we can discuss the direction.

## Related projects

- [aws-containers/amazon-ecs-exec-checker](https://github.com/aws-containers/amazon-ecs-exec-checker) — the original bash-based checker

## License

Distributed under the [Apache-2.0](LICENSE) license.
