// verify-exec diagnoses whether ECS Exec can be used against a
// specific (cluster, task-id) pair.
//
// Exit codes: 0 = all ok / 1 = warn findings with --fail-on warn /
// 2 = error findings / 3 = tool failure (auth error, task not found, …).
// Keeping 2 and 3 distinct lets CI tell "misconfigured for ECS Exec"
// apart from "the tool could not run".
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/toricls/verify-exec/internal/checks"
	"github.com/toricls/verify-exec/internal/collect"
	"github.com/toricls/verify-exec/internal/report"
	"github.com/toricls/verify-exec/internal/runner"
)

const (
	exitOK          = 0
	exitWarn        = 1
	exitError       = 2
	exitToolFailure = 3
)

// version is stamped at build time via -ldflags (see the Makefile).
var version = "dev"

type options struct {
	container string
	profile   string
	region    string
	output    string
	failOn    string
}

func main() {
	os.Exit(run())
}

func run() int {
	opts := options{}
	exitCode := exitOK

	root := &cobra.Command{
		Use:           "verify-exec <cluster> <task-id>",
		Short:         "Diagnose whether ECS Exec can be used against a task",
		Version:       version,
		Args:          cobra.ExactArgs(2),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			code, err := execute(cmd.Context(), args[0], args[1], opts)
			exitCode = code
			return err
		},
	}
	root.Flags().StringVar(&opts.container, "container", "", "limit container-level checks to this container")
	root.Flags().StringVar(&opts.profile, "profile", "", "AWS profile")
	root.Flags().StringVar(&opts.region, "region", "", "AWS region")
	root.Flags().StringVar(&opts.output, "output", "table", "output format: table|json")
	root.Flags().StringVar(&opts.failOn, "fail-on", "error", "exit non-zero on: error|warn")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		if exitCode == exitOK {
			exitCode = exitToolFailure
		}
	}
	return exitCode
}

func execute(ctx context.Context, cluster, taskID string, opts options) (int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var renderer report.Renderer
	switch opts.output {
	case "table":
		if term.IsTerminal(int(os.Stdout.Fd())) {
			// Live fixed-row TUI; a user interrupt cancels the run.
			renderer = report.NewTUIRenderer(os.Stdout, cancel)
		} else {
			// Non-TTY (pipes, CI): append in completion order instead.
			renderer = report.NewPlainRenderer(os.Stdout)
		}
	case "json":
		renderer = report.NewJSONRenderer(os.Stdout)
	default:
		return exitToolFailure, fmt.Errorf("invalid --output %q (want table or json)", opts.output)
	}
	if opts.failOn != "error" && opts.failOn != "warn" {
		return exitToolFailure, fmt.Errorf("invalid --fail-on %q (want error or warn)", opts.failOn)
	}

	var cfgOpts []func(*config.LoadOptions) error
	if opts.profile != "" {
		cfgOpts = append(cfgOpts, config.WithSharedConfigProfile(opts.profile))
	}
	if opts.region != "" {
		cfgOpts = append(cfgOpts, config.WithRegion(opts.region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return exitToolFailure, fmt.Errorf("failed to load AWS config: %w", err)
	}
	if cfg.Region == "" {
		return exitToolFailure, fmt.Errorf("AWS region is not set; use --region or configure a default region")
	}

	snapshot := collect.Collect(ctx, collect.Deps{
		ECS:  ecs.NewFromConfig(cfg),
		STS:  sts.NewFromConfig(cfg),
		IAM:  iam.NewFromConfig(cfg),
		EC2:  ec2.NewFromConfig(cfg),
		KMS:  kms.NewFromConfig(cfg),
		Logs: cloudwatchlogs.NewFromConfig(cfg),
		S3:   s3.NewFromConfig(cfg),
	}, cluster, taskID)

	findings, runErr := runner.Run(ctx, runner.Options{
		Checks:    checks.All(),
		Snapshot:  snapshot,
		Renderer:  renderer,
		TaskID:    taskID,
		Container: opts.container,
	})

	target := report.Target{Cluster: cluster, TaskArn: taskID, Region: cfg.Region}
	if task, err := snapshot.Task.Get(ctx); err == nil {
		target.TaskArn = aws.ToString(task.TaskArn)
	}

	summary := report.Summarize(target, findings)
	if err := renderer.Close(summary); err != nil {
		return exitToolFailure, fmt.Errorf("failed to render output: %w", err)
	}

	if runErr != nil {
		return exitToolFailure, runErr
	}
	switch {
	case summary.Error > 0:
		return exitError, nil
	case summary.Warn > 0 && opts.failOn == "warn":
		return exitWarn, nil
	default:
		return exitOK, nil
	}
}
