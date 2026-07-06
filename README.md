# verify-exec

## Checks

### LOCAL — Local execution environment

This tool assumes the user's execution environment is "AWS CLI + Session Manager Plugin". Both are **must conditions (always error)**.

| ID | Check | Level on failure | Depends on | Applicability |
|---|---|---|---|---|
| LOCAL-001 | Session Manager Plugin is installed (locate `session-manager-plugin` on PATH and run `--version`) | error | None | Always |
| LOCAL-002 | AWS CLI is installed and its version is v1.22.3+ / v2.3.6+ (parse `aws --version`) | error | None | Always |

### TASK — Task runtime state

| ID | Check | Level on failure | Depends on | Applicability |
|---|---|---|---|---|
| TASK-001 | The task is `RUNNING`. `PROVISIONING`/`PENDING`/`ACTIVATING` are warn (still starting); `DEACTIVATING` and later, and `STOPPED`, are error | error / warn | Task | Always |
| TASK-002 | `enableExecuteCommand = true` | error | Task | Always |
| TASK-003 | The ManagedAgent `ExecuteCommandAgent` is `RUNNING` in each container (**emit container-granularity findings**; include the `reason` in the message when stopped) | error | Task | Always |

### TDEF — Task definition

| ID | Check | Level on failure | Depends on | Applicability |
|---|---|---|---|---|
| TDEF-001 | `readonlyRootFilesystem` is not `true` on any container (container granularity) | error | TaskDefinition | Always |

